#!/usr/bin/env python3

import struct
import math
from datetime import datetime
from collections import namedtuple

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

def etl_frames(etl_data):
    b = Buf(etl_data)

    ndis_provider = guid_to_bytes('2ed6006e-4729-4609-b423-3ee7bcd678ef')
    
    while b.off < len(b.data):
        wmi_start = b.off
        #print("WMI 0x%x"%wmi_start)
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
            print("skipping compressed WMI_BUFFER at 0x%x"%wmi_start)
        else:
            while b.off < wmi_start+wmi_useful_size:
                ev_start = b.off
                #print("EV 0x%x"%ev_start)                
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
                b.set(ev_start + max(0, ev_size))
                al = 8 - (b.off%8)
                if al < 8:
                    b.skip_bytes(al)
                    
            b.set(wmi_start+wmi_size)

def etl_to_pcap(etl_fn, pcap_fn):

    etl_data = None

    info("reading etl file %s in memory..."%etl_fn)
    with open(etl_fn, 'rb') as f:
        etl_data = f.read()

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

        info("looking for etl frames...")
        frames = []
        for t, data in etl_frames(etl_data):
            print("found frame at t=%d, %d bytes"%(t, len(data)))
            frames.append((t, data))

        info("sorting %d frames by timestamp..."%(len(frames)))
        frames.sort(key=lambda x: x[0])

        info("writing frames to pcap...")
        for t, data in frames:
            unix = filetime_to_epoch(t)
            usec, sec = math.modf(unix)
            usec = int(usec*1000)
            sec = int(sec)
            print("writing frame at t=%s.%d, %d bytes..."%(epoch_to_str(sec), usec, len(data)))
            f.write(struct.pack('<I', sec))
            f.write(struct.pack('<I', usec))
            f.write(struct.pack('<I', len(data)))
            f.write(struct.pack('<I', len(data)))
            f.write(data)
            

        info("closing...")

    info("dumped %d frames to %s. done."%(len(frames), pcap_fn))


def main():
    etl_to_pcap(r'c:/users/aaptel/documents/dev/etlre/trace.etl',
                r'c:/users/aaptel/documents/dev/etlre/trace2.pcap')
    return 0
    
    
    data = None
    with open(r'c:/users/aaptel/documents/dev/etlre/trace.etl', 'rb') as f:
        data = f.read()
    buf = Buf(data)

    r = []
    while buf.off < len(data):
        e = EtwBuffer(buf)
        #pp(e)
        r.append(e)

    ehs = []
    pcap = PCap()
    ndisprovider = GUID(string='2ed6006e-4729-4609-b423-3ee7bcd678ef')
    for ibuf,b in enumerate(r):
        for iev, e in enumerate(b.events):
            if isinstance(e.header, EventHeader) and ndisprovider == e.header.provider_id:
                print("BUF[%d][%d]"%(ibuf, iev))
                t = time_win_to_unix(b.header.timestamp+e.header.timestamp)
                print(time_str(int(t)))

                pp(e)
                ehs.append(e)
                ndis = NDisEtwProvider(Buf(e.data))
                usec, sec = math.modf(t)
                pcap.add_pkt(ndis.payload, int(sec), int(usec*1000))
                
    print("NB %d"%len(ehs))
    pcap.write("trace.pcap")

def shorten(x):
    if not isinstance(x, str):
        x = str(x)
    if len(x) > 300:
        x = x[:300]+"..."
    return x


def time_str(t):
    return datetime.utcfromtimestamp(t).strftime('%Y-%m-%d %H:%M:%S')

def time_win_to_unix(t):
    start = 0x019DB1DED53E8000;
    ticks_per_sec = 10000000
    return (t-start)/ticks_per_sec
    

class PCap:
    def __init__(self, tz=0, max_len=65535):
        self.tz = tz
        self.max_len = max_len
        self.pkts = []

    def add_pkt(self, data, sec, usec):
        self.pkts.append((data, sec, usec))

    def write(self, fn):
        with open(fn, 'wb+') as f:
            f.write(struct.pack('<I', 0xa1b2c3d4)) # magic
            f.write(struct.pack('<H', 2)) # major version
            f.write(struct.pack('<H', 4)) # minor version
            f.write(struct.pack('<i', self.tz)) # local time seconds offset to gmt
            f.write(struct.pack('<I', 0)) # sigfigs
            f.write(struct.pack('<I', self.max_len)) # max pkt len
            f.write(struct.pack('<I', 1)) # ethernet

            for pkt in sorted(self.pkts, key=lambda x: x[1]*1000+x[2]):
                data, sec, usec = pkt
                print(data)
                assert(len(data) <= self.max_len)
                f.write(struct.pack('<I', sec))
                f.write(struct.pack('<I', usec))
                f.write(struct.pack('<I', len(data)))
                f.write(struct.pack('<I', len(data)))
                f.write(data)

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


class NDisEtwProvider:
    def __init__(self, b=None):
        self.miniport_if_index = 0
        self.lower_if_index = 0
        self.fragment_size = 0
        if b:
            self.read(b)

    def read(self, b):
        self.miniport_if_index = b.read('<I')
        self.lower_if_index = b.read('<I')
        self.fragment_size = b.read('<I')
        self.payload = b.read_bytes(self.fragment_size)
    
class GUID:
    def __init__(self, b=None, string=None):
        self.a = 0
        self.b = 0
        self.c = 0
        self.d = 0
        self.e = 0
        if b:
            self.read(b)
        elif string:
            self.a, self.b, self.c, self.d, self.e = [int(x, 16) for x in string.split('-')]

    def read(self, b):
        self.a = b.read('<I')
        self.b = b.read('<H')
        self.c = b.read('<H')
        self.d = b.read('>H')
        self.e = (b.read('>I') << 16) + b.read('>H')

    def __str2__(self):
        return "%08x-%04x-%04x-%04x-%012x / %d-%d-%d-%d-%d"%(self.a, self.b, self.c, self.d, self.e, self.a, self.b, self.c, self.d, self.e)

    def __eq__(self, o):
        return self.a == o.a and self.b == o.b and self.c == o.c and self.d == o.d and self.e == self.e

class TraceLogfileHeader:
    def __init__(self, b=None):
        self.buffer_size = 0
        self.major_version = 0
        self.minor_version = 0
        self.sub_version = 0
        self.sub_minor_version = 0
        self.provider_version = 0
        self.number_of_processors = 0
        self.end_time = 0
        self.timer_resolution = 0
        self.maximum_file_size = 0
        self.log_file_mode = 0
        self.buffers_written = 0
        self.start_buffers = 0
        self.pointer_size = 0
        self.events_lost = 0
        self.cpu_speed = 0
        self.logger_name_ptr = 0
        self.log_file_name_ptr = 0
        self.time_zone = bytes(176)
        self.boot_time = 0
        self.perf_freq = 0
        self.start_time = 0
        self.reserved_flags = 0
        self.buffers_lost = 0
        self.logger_name = ""
        self.log_file_name = ""
        if b:
            self.read(b)


    def read(self, b):
        self.buffer_size = b.read('<I')
        self.major_version = b.read('B')
        self.minor_version = b.read('B')
        self.sub_version = b.read('B')
        self.sub_minor_version = b.read('B')
        self.provider_version = b.read('<I')
        self.number_of_processors = b.read('<I')
        self.end_time = b.read('<q')
        self.timer_resolution = b.read('<I')
        self.maximum_file_size = b.read('<I')
        self.log_file_mode = b.read('<I')
        self.buffers_written = b.read('<I')
        self.start_buffers = b.read('<I')
        self.pointer_size = b.read('<I')
        self.events_lost = b.read('<I')
        self.cpu_speed = b.read('<I')
        self.logger_name_ptr = b.read('<q')
        self.log_file_name_ptr = b.read('<q')
        self.time_zone = b.read_bytes(176)
        self.boot_time = b.read('<q')
        self.perf_freq = b.read('<q')
        self.start_time = b.read('<q')
        self.reserved_flags = b.read('<I')
        self.buffers_lost = b.read('<I')
        self.logger_name = b.read_ucs2_str()
        self.log_file_name = b.read_ucs2_str()

class SystemTraceHeader:
    def __init__(self, b=None, full=False):
        self.version = 0
        self.header_type = 0
        self.marker_flags = 0
        self.size = 0
        self.hook_id = 0
        self.thread_id = 0
        self.process_id = 0
        self.system_time = 0

        self.kernel_time = 0
        self.user_time = 0
        if b:
            self.read(b, full)

    def read(self, b, full=False):
        self.version = b.read('<H')
        self.header_type = b.read('B')
        self.marker_flags = b.read('B')
        self.size = b.read('<H')
        self.hook_id = b.read('<H')
        self.thread_id = b.read('<I')
        self.process_id = b.read('<I')
        self.system_time = b.read('<q')

        if full:
            self.kernel_time = b.read('<I')
            self.user_time = b.read('<I')

class PerfInfoTraceHeader:
    def __init__(self, b=None):
        self.version = 0
        self.header_type = 0
        self.marker_flags = 0
        self.size = 0
        self.hook_id = 0
        self.system_type = 0
        if b:
            self.read(b)


    def read(self, b):
        self.version = b.read('<H')
        self.header_type = b.read('B')
        self.marker_flags = b.read('B')
        self.size = b.read('<H')
        self.hook_id = b.read('<H')
        self.system_type = b.read('<q')

class EventTraceHeader:
    def __init__(self, b=None):
        self.size = 0
        self.header_type = 0
        self.marker_flags = 0
        self.event_type = 0
        self.level = 0
        self.version = 0
        self.thread_id = 0
        self.process_id = 0
        self.timestamp = 0
        self.guid = GUID()
        self.kernel_time = 0
        self.user_time = 0
        if b:
            self.read(b)


    def read(self, b):
        self.size = b.read('<H')
        self.header_type = b.read('B')
        self.marker_flags = b.read('B')
        self.event_type = b.read('B')
        self.level = b.read('<B')
        self.version = b.read('<H')
        self.thread_id = b.read('<I')
        self.process_id = b.read('<I')
        self.timestamp = b.read('<q')
        self.guid = GUID(b)
        self.kernel_time = b.read('<H')
        self.user_time = b.read('<H')

class EventInstanceGuidHeader:
    def __init__(self, b=None):
        self.size = 0
        self.header_type = 0
        self.marker_flags = 0
        self.event_type = 0
        self.level = 0
        self.version = 0
        self.thread_id = 0
        self.process_id = 0
        self.timestamp = 0
        self.guid = GUID()
        self.kernel_time = 0
        self.user_time = 0
        self.instance_id = 0
        self.parent_instance_id = 0
        self.parent_guid = GUID()
        if b:
            self.read(b)

    def read(self, b):
        self.size = b.read('<H')
        self.header_type = b.read('B')
        self.marker_flags = b.read('B')
        self.event_type = b.read('B')
        self.level = b.read('<B')
        self.version = b.read('<H')
        self.thread_id = b.read('<I')
        self.process_id = b.read('<I')
        self.timestamp = b.read('<q')
        self.guid = GUID(b)
        self.kernel_time = b.read('<H')
        self.user_time = b.read('<H')
        self.instance_id = 0
        self.parent_instance_id = 0
        self.parent_guid = GUID(b)



class EventHeader:
    def __init__(self, b=None):
        self.size = 0
        self.header_type = 0
        self.marker_flags = 0
        self.flags = 0
        self.event_property = 0
        self.thread_id = 0
        self.process_id = 0
        self.timestamp = 0
        self.provider_id = 0

        # EVENT_DESCRIPTOR
        self.id = 0
        self.version = 0
        self.channel = 0
        self.level = 0
        self.opcode = 0
        self.task = 0
        self.keyword = 0

        self.kernel_time = 0
        self.user_time = 0
        self.activity_id = 0
        if b:
            self.read(b)

    def read(self, b):
        self.size = b.read('<H')
        self.header_type = b.read('B')
        self.marker_flags = b.read('B')
        self.flags = b.read('<H')
        self.event_property = b.read('<H')
        self.thread_id = b.read('<I')
        self.process_id = b.read('<I')
        self.timestamp = b.read('<q')
        self.provider_id = GUID(b)

        # EVENT_DESCRIPTOR
        self.id = b.read('<H')
        self.version = b.read('B')
        self.channel = b.read('B')
        self.level = b.read('B')
        self.opcode = b.read('B')
        self.task = b.read('<H')
        self.keyword = b.read('<Q')

        self.kernel_time = b.read('<I')
        self.user_time = b.read('<I')
        self.activity_id = GUID(b)


class EtwEvent:
    def __init__(self, b=None):
        self.header = None
        self.data = None
        if b:
            self.read(b)

    def read(self, b):
        r = []
        v = b.peek('B', 2)

        start = b.off

        if v == 1 or v == 2:
            # TRACE_HEADER_TYPE_SYSTEM32
            # TRACE_HEADER_TYPE_SYSTEM64
            self.header = SystemTraceHeader(b, full=True)
            if self.header.hook_id == 0:
                self.data = TraceLogfileHeader(b)
            else:
                self.data = b.read_bytes(self.header.size - (b.off-start))

        elif v == 3 or v == 4:
            # TRACE_HEADER_TYPE_COMPACT32
            # TRACE_HEADER_TYPE_COMPACT64
            self.header = SystemTraceHeader(b, full=False)
            if self.header.hook_id == 0:
                self.data = TraceLogfileHeade(b)
            else:
                self.data = b.read_bytes(self.header.size - (b.off-start))

        elif v == 16 or v == 17:
            # TRACE_HEADER_TYPE_PERFINFO32
            # TRACE_HEADER_TYPE_PERFINFO64
            self.header = PerfInfoTraceHeader(b)
            self.data = b.read_bytes(self.header.size - (b.off-start))

        elif v == 10 or v == 20:
            # TRACE_HEADER_TYPE_FULL_HEADER32
            # TRACE_HEADER_TYPE_FULL_HEADER64
            self.header = EventTraceHeader(b)
            self.data = b.read_bytes(self.header.size - (b.off-start))

        elif v == 18 or v == 19:
            # TRACE_HEADER_TYPE_EVENT_HEADER32
            # TRACE_HEADER_TYPE_EVENT_HEADER64
            self.header = EventHeader(b)
            self.data = b.read_bytes(self.header.size - (b.off-start))

        elif v == 11 or v == 21:
            # TRACE_HEADER_TYPE_INSTANCE_HEADER32
            # TRACE_HEADER_TYPE_INSTANCE_HEADER64
            self.header = EventInstanceGuidHeader(b)
            self.data = b.read_bytes(self.header.size - (b.off-start))

        # elif v == 13:
        #     raise Exception("TRACE_HEADER_TYPE_ERROR")

        # elif v == 15:
        #     raise Exception("TRACE_HEADER_TYPE_MESSAGE")
        else:
            self.header = None
            size = b.read('<H')
            self.data = b.read_bytes(max(size-2, 0))

        al = 8 - (b.off%8)
        if al < 8:
            self.padding = b.read_bytes(al)



# Buffer Types
GENERIC      = 0
RUNDOWN      = 1
CTX_SWAP     = 2
REFTIME      = 3
HEADER       = 4
BATCHED      = 5
EMPTY_MARKER = 6
DBG_INFO     = 7
MAXIMUM      = 8

class WMIBufferHeader:
    def __init__(self, b=None):
        self.buffer_size = 0
        self.saved_offset = 0
        self.current_offset = 0
        self.reference_count = 0
        self.timestamp = 0
        self.sequence_number = 0
        self.clock_type = 0
        self.frequency = 0

        # ETW_BUFFER_CONTEXT
        self.processor_number = 0
        self.alignement = 0
        self.logger_id = 0

        # ETW_BUFFER_STATE
        self.buffer_state = 0

        self.offset = 0
        self.buffer_flag = 0
        self.buffer_type = 0

        self.start_time = 0
        self.start_perf_clock = 0
        if b:
            self.read(b)

    def read(self, b):
        self.buffer_size = b.read('<I')
        self.saved_offset = b.read('<I')
        self.current_offset = b.read('<I')
        self.reference_count = b.read('<i')
        self.timestamp = b.read('<q')
        self.sequence_number = b.read('<q')
        v = b.read('<Q')
        self.clock_type = v & 0b111
        self.frequency = v >> 3

        self.processor_number = b.read('B')
        self.alignement = b.read('B')
        self.logger_id = b.read('<H')

        self.buffer_state = b.read('<I')
        self.offset = b.read('<I')
        self.buffer_flag = b.read('<H')
        self.buffer_type = b.read('<H')

        self.start_time = b.read('<q')
        self.start_perf_clock = b.read('<q')



class EtwBuffer:
    def __init__(self, b=None):
        self.header = WMIBufferHeader()
        self.events = []
        if b:
            self.read(b)

    def read(self, b):
        start = b.off
        self.header = WMIBufferHeader(b)
        if self.header.buffer_flag & 0x40:
            self.compressed = shorten(b.read_bytes(self.header.buffer_size - (b.off-start)))
        else:
            while b.off < start+self.header.offset:
                self.events.append(EtwEvent(b))
            self.padding = shorten(b.read_bytes(self.header.buffer_size - (b.off-start)))


def pp(clas, indent=0):
    print(' ' * indent +  type(clas).__name__ +  ':')
    indent += 4
    for k,v in clas.__dict__.items():
        if '__str2__' in dir(v):
            print(' '*indent + k + ': ' + v.__str2__())
        elif '__dict__' in dir(v):
            pp(v,indent)
        else:
            print(' ' * indent +  k + ': ' + str(v))

if __name__ == '__main__':
    main()
