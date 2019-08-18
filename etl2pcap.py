#!/usr/bin/env python3
#
# etl2pcap: extract network frames from ETL trace files and export them to .pcap
#
# Copyright (C) 2019  Aurelien Aptel <aurelien.aptel@gmail.com>
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software Foundation,
# Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
#

import struct
import math
from datetime import datetime
import sys
import argparse
import os

VERBOSE = False

def main():
    global VERBOSE

    ap = argparse.ArgumentParser(description="Extract network frames from ETL trace file and export them to .pcap")
    ap.add_argument("--verbose", help="print more information while processing", action="store_true", default=False)
    ap.add_argument("etl", help="path to etl file to process")
    ap.add_argument("pcap", nargs='?', help="path to pcap file to write to. defaults to same name as input with the .pcap extension", default=None)
    args = ap.parse_args()

    if args.pcap is None:
        if args.etl[-4:].lower() == '.etl':
            args.pcap = args.etl[:-4]+".pcap"
        else:
            args.pcap = args.etl+".pcap"

    if args.verbose:
        VERBOSE = True
            
    if not os.path.exists(args.etl):
        print("%s doesn't exist"%args.etl)
        exit(1)

    etl_to_pcap(args.etl, args.pcap)

def etl_frames(etl_data):
    b = Buf(etl_data)

    ndis_provider = guid_to_bytes('2ed6006e-4729-4609-b423-3ee7bcd678ef')

    while b.off < len(b.data):
        wmi_start = b.off
        dbg("WMI 0x%x"%wmi_start)
        # WMI_BUFFER_HEADER
        wmi_size = b.read('<I')
        b.skip('<IIi')
        start_timestamp = b.read('<q')
        b.skip('<qQBBHI')
        wmi_useful_size = b.read('<I')
        flags = b.read('<H')
        b.skip('<Hqq')

        if flags & 0x40:
            # compressed, skip
            dbg("skipping compressed WMI_BUFFER at 0x%x"%wmi_start)
        else:
            while b.off < wmi_start+wmi_useful_size:
                ev_start = b.off
                dbg("EV 0x%x"%ev_start)
                ev_size = b.read('<H')
                ev_type = b.read('<B')
                b.set(ev_start)

                if ev_type in [1,2,3,4,16,17]:
                    b.skip('<HBB')
                    ev_size = b.read('<H')
                    b.set(ev_start)

                elif ev_type == 18 or ev_type == 19:
                    b.skip('<HBBHHII')
                    off_timestamp = b.read('<q')
                    ev_provider = b.read_bytes(16)
                    if ev_provider == ndis_provider:
                        b.skip('<HBBBBHQII 16B')
                        b.skip('<II')
                        frag_size = b.read('<I')
                        ev_left = ev_size - (b.off-ev_start)
                        assert(frag_size == ev_left)
                        t = start_timestamp + off_timestamp

                        yield (t, b.read_bytes(ev_size - (b.off - ev_start)))

                assert(ev_size > 0 and ev_start+ev_size <= wmi_start+wmi_useful_size)
                b.set(ev_start + ev_size)
                al = 8 - (b.off%8)
                if al < 8:
                    b.skip_bytes(al)

            b.set(wmi_start+wmi_size)

def etl_to_pcap(etl_fn, pcap_fn):

    etl_data = None

    info("reading etl file %s in memory..."%etl_fn)
    with open(etl_fn, 'rb') as f:
        etl_data = f.read()

    info("looking for etl frames...")
    frames = []
    for t, data in etl_frames(etl_data):
        dbg("found frame at t=%d, %d bytes"%(t, len(data)))
        frames.append((t, data))

    info("sorting %d frames by timestamp..."%(len(frames)))
    frames.sort(key=lambda x: x[0])

    info("opening pcap file %s for writing..."%pcap_fn)
    with open(pcap_fn, 'wb+') as f:
        info("writing pcap header")
        f.write(struct.pack('<I', 0xa1b2c3d4)) # magic
        f.write(struct.pack('<H', 2)) # major version
        f.write(struct.pack('<H', 4)) # minor version
        f.write(struct.pack('<i', 0)) # local time seconds offset to gmt
        f.write(struct.pack('<I', 0)) # sigfigs
        f.write(struct.pack('<I', 65535)) # max pkt len
        f.write(struct.pack('<I', 1)) # ethernet
        
        info("writing frames to pcap...")
        for t, data in frames:
            unix = filetime_to_epoch(t)
            usec, sec = math.modf(unix)
            usec = int(usec*1000)
            sec = int(sec)
            dbg("writing frame at t=%s.%d, %d bytes..."%(epoch_to_str(sec), usec, len(data)))
            f.write(struct.pack('<I', sec))
            f.write(struct.pack('<I', usec))
            f.write(struct.pack('<I', len(data)))
            f.write(struct.pack('<I', len(data)))
            f.write(data)

        info("closing...")

    info("dumped %d frames to %s. done."%(len(frames), pcap_fn))

class Buf:
    def __init__(self, data):
        self.data = data
        self.off = 0

    def peek(self, fmt, off):
        return struct.unpack_from(fmt, self.data, self.off+off)[0]

    def read(self, fmt):
        size = struct.calcsize(fmt)
        r = struct.unpack_from(fmt, self.data, self.off)[0]
        self.off += size
        return r

    def set(self, off):
        # allow setting at the exact end
        assert(0 <= off <= len(self.data))
        self.off = off

    def skip(self, fmt):
        size = struct.calcsize(fmt)
        assert(self.off + size < len(self.data))
        self.off += size

    def read_bytes(self, n):
        assert(n >= 0)
        r = self.data[self.off:self.off+n]
        self.off += n
        return r

    def skip_bytes(self, n):
        assert(n >= 0)
        self.off += n

    def read_ucs2_str(self):
        buf = bytearray()
        c = self.read('<H')
        while c != 0:
            buf.append((c>>8) & 0xff)
            buf.append(c & 0xff)
            c = self.read('H')
        return buf.decode('utf-16-be')

def dbg(s):
    if VERBOSE:
        print(s)
    
def info(s):
    print("[*]",s)

def filetime_to_epoch(t):
    start = 0x019DB1DED53E8000;
    ticks_per_sec = 10000000
    return (t-start)/ticks_per_sec

def epoch_to_str(t):
    return datetime.utcfromtimestamp(t).strftime('%Y-%m-%d %H:%M:%S')

def guid_to_bytes(g):
    a,b,c,d,e = [int(x, 16) for x in g.split("-")]
    return struct.pack('<IHH', a,b,c) + struct.pack('>HIH', d, e>>16, e & 0xffff)



if __name__ == '__main__':
    main()
