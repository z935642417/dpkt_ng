# -*- coding: utf-8 -*-
"""Enhanced Interior Gateway Routing Protocol."""
from __future__ import absolute_import
from __future__ import print_function

import struct

from . import dpkt

# Opcodes
EIGRP_OP_UPDATE = 1
EIGRP_OP_QUERY = 3
EIGRP_OP_REPLY = 4
EIGRP_OP_HELLO = 5
EIGRP_OP_SIAQUERY = 10
EIGRP_OP_SIAREPLY = 11

# Flags
EIGRP_FLAG_INIT = 0x01
EIGRP_FLAG_CONDITIONAL_RECEIVE = 0x02
EIGRP_FLAG_RESTART = 0x04
EIGRP_FLAG_ENDOFTABLE = 0x08

# TLV types
EIGRP_TLV_PARAM = 0x0001
EIGRP_TLV_AUTH = 0x0002
EIGRP_TLV_INTERNAL_ROUTE = 0x0102
EIGRP_TLV_EXTERNAL_ROUTE = 0x0103

# Wide Metrics sub-TLV types
EIGRP_METRIC_SCALED = 0x0601
EIGRP_METRIC_EXTENDED = 0x0602

# Address Family Identifiers
AFI_IPV4 = 1
AFI_IPV6 = 16384


class EIGRPTLV(object):
    """Base TLV: type(2B) + length(2B) + value(variable)."""
    def __init__(self, buf=None):
        self.type = 0
        self.length = 4
        self.value = b''
        if buf:
            self.unpack(buf)

    def unpack(self, buf):
        self.type, self.length = struct.unpack('>HH', buf[:4])
        self.value = buf[4:self.length]

    def __bytes__(self):
        return struct.pack('>HH', self.type, self.length) + self.value

    def __len__(self):
        return self.length


class EIGRPGenericTLV(EIGRPTLV):
    """Fallback TLV for unknown types."""
    pass


class EIGRPParamTLV(EIGRPTLV):
    """EIGRP Parameter TLV (0x0001)."""
    def __init__(self, k1=0, k2=0, k3=1, k4=0, k5=0, hold_time=15):
        self.k1 = k1; self.k2 = k2; self.k3 = k3
        self.k4 = k4; self.k5 = k5
        self.hold_time = hold_time

    def unpack(self, buf):
        EIGRPTLV.unpack(self, buf)
        if len(self.value) >= 10:
            self.k1, self.k2, self.k3, self.k4, self.k5 = \
                struct.unpack('BBBBB', self.value[:5])
            self.hold_time = struct.unpack('>H', self.value[8:10])[0]

    def __bytes__(self):
        value = struct.pack('BBBBB3sH', self.k1, self.k2, self.k3,
                           self.k4, self.k5, b'\x00' * 3, self.hold_time)
        self.length = 4 + len(value)
        return struct.pack('>HH', EIGRP_TLV_PARAM, self.length) + value


class EIGRPScaledMetricTLV(EIGRPTLV):
    """Wide Metric: Scaled delay + bandwidth (0x0601)."""
    def unpack(self, buf):
        EIGRPTLV.unpack(self, buf)
        if len(self.value) >= 8:
            self.scaled_delay = struct.unpack('>I', self.value[0:4])[0]
            self.scaled_bandwidth = struct.unpack('>I', self.value[4:8])[0]


class EIGRPExtendedMetricTLV(EIGRPTLV):
    """Wide Metric: Jitter + energy (0x0602)."""
    def unpack(self, buf):
        EIGRPTLV.unpack(self, buf)
        if len(self.value) >= 9:
            self.jitter = struct.unpack('>I', self.value[0:4])[0]
            self.energy = struct.unpack('>I', self.value[4:8])[0]
            self.rflags = self.value[8]


class EIGRPGenericMetricTLV(EIGRPTLV):
    pass


class EIGRPInternalRouteTLV(EIGRPTLV):
    """EIGRP Internal Route TLV (0x0102)."""
    _metric_sw = {
        EIGRP_METRIC_SCALED: EIGRPScaledMetricTLV,
        EIGRP_METRIC_EXTENDED: EIGRPExtendedMetricTLV,
    }

    def __init__(self, *args, **kwargs):
        self.next_hop = 0; self.delay = 0; self.bandwidth = 0; self.mtu = 1500
        self.hop_count = 0; self.reliability = 255; self.load = 1
        self.prefix_length = 0; self.prefix = b''; self.metrics = []
        if args and isinstance(args[0], (bytes, bytearray)):
            self.unpack(args[0])

    def unpack(self, buf):
        EIGRPTLV.unpack(self, buf)
        if len(self.value) < 26:
            return
        offset = 0
        self.next_hop = struct.unpack('>I', self.value[offset:offset+4])[0]; offset += 4
        self.delay = struct.unpack('>I', self.value[offset:offset+4])[0]; offset += 4
        self.bandwidth = struct.unpack('>I', self.value[offset:offset+4])[0]; offset += 4
        self.mtu = struct.unpack('>I', self.value[offset:offset+3] + b'\x00')[0] >> 8; offset += 3
        self.hop_count = self.value[offset]; offset += 1
        self.reliability = self.value[offset]; offset += 1
        self.load = self.value[offset]; offset += 1
        offset += 2
        self.prefix_length = self.value[offset]; offset += 1
        prefix_bytes = (self.prefix_length + 7) // 8
        self.prefix = self.value[offset:offset + prefix_bytes]
        offset += prefix_bytes
        self.metrics = []
        while offset + 4 <= len(self.value):
            stype, slen = struct.unpack('>HH', self.value[offset:offset+4])
            if slen < 4 or offset + slen > len(self.value): break
            cls = self._metric_sw.get(stype, EIGRPGenericMetricTLV)
            self.metrics.append(cls(self.value[offset:offset+slen]))
            offset += slen

    def __bytes__(self):
        prefix_bytes = (self.prefix_length + 7) // 8
        value = struct.pack('>III', self.next_hop, self.delay, self.bandwidth)
        value += struct.pack('>I', self.mtu << 8)[:3]
        value += bytes([self.hop_count, self.reliability, self.load, 0, 0, self.prefix_length])
        value += self.prefix.ljust(prefix_bytes, b'\x00')[:prefix_bytes]
        for m in self.metrics: value += bytes(m)
        self.length = 4 + len(value)
        return struct.pack('>HH', EIGRP_TLV_INTERNAL_ROUTE, self.length) + value


class EIGRPExternalRouteTLV(EIGRPInternalRouteTLV):
    """EIGRP External Route TLV (0x0103)."""
    def __init__(self, *args, **kwargs):
        self.origin_router = 0; self.origin_as = 0; self.tag = 0
        self.ext_proto = 0; self.ext_flags = 0
        EIGRPInternalRouteTLV.__init__(self, *args, **kwargs)

    def unpack(self, buf):
        EIGRPInternalRouteTLV.unpack(self, buf)
        prefix_bytes = (self.prefix_length + 7) // 8
        ext_offset = 21 + prefix_bytes
        if ext_offset + 13 <= len(self.value):
            self.origin_router = struct.unpack('>I', self.value[ext_offset:ext_offset+4])[0]
            self.origin_as = struct.unpack('>I', self.value[ext_offset+4:ext_offset+8])[0]
            self.tag = struct.unpack('>I', self.value[ext_offset+8:ext_offset+12])[0]
            self.ext_proto = self.value[ext_offset+12]
            self.ext_flags = self.value[ext_offset+13]

    def __bytes__(self):
        prefix_bytes = (self.prefix_length + 7) // 8
        value = struct.pack('>III', self.next_hop, self.delay, self.bandwidth)
        value += struct.pack('>I', self.mtu << 8)[:3]
        value += bytes([self.hop_count, self.reliability, self.load, 0, 0, self.prefix_length])
        value += self.prefix.ljust(prefix_bytes, b'\x00')[:prefix_bytes]
        value += struct.pack('>IIIBB2s', self.origin_router, self.origin_as,
                            self.tag, self.ext_proto, self.ext_flags, b'\x00'*2)
        for m in self.metrics: value += bytes(m)
        self.length = 4 + len(value)
        return struct.pack('>HH', EIGRP_TLV_EXTERNAL_ROUTE, self.length) + value


class EIGRP(dpkt.Packet):
    """EIGRP Protocol Packet."""
    __byte_order__ = '>'
    __hdr__ = (
        ('v', 'B', 2),
        ('opcode', 'B', 0),
        ('sum', 'H', 0),
        ('flags', 'I', 0),
        ('seq', 'I', 0),
        ('ack', 'I', 0),
        ('asn', 'I', 0),
    )
    _tlv_sw = {
        EIGRP_TLV_PARAM: EIGRPParamTLV,
        EIGRP_TLV_INTERNAL_ROUTE: EIGRPInternalRouteTLV,
        EIGRP_TLV_EXTERNAL_ROUTE: EIGRPExternalRouteTLV,
    }
    _opcode_sw = {}

    def __bytes__(self):
        if not self.sum:
            self.sum = dpkt.in_cksum(dpkt.Packet.__bytes__(self))
        return dpkt.Packet.__bytes__(self)

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        cls = self._opcode_sw.get(self.opcode)
        if cls:
            self.data = cls(self.data)
            setattr(self, getattr(self.data, '_msg_name', self.data.__class__.__name__).lower(), self.data)


class _EIGRPMessageMixin(object):
    def __bytes__(self):
        return self._buf

    def _parse_tlvs(self, buf):
        tlvs = []
        off = 0
        while off + 4 <= len(buf):
            tlv_type, tlv_len = struct.unpack('>HH', buf[off:off+4])
            if tlv_len < 4 or off + tlv_len > len(buf):
                break
            cls = EIGRP._tlv_sw.get(tlv_type, EIGRPGenericTLV)
            tlvs.append(cls(buf[off:off+tlv_len]))
            off += tlv_len
        return tlvs


class EIGRPHello(_EIGRPMessageMixin, dpkt.Packet):
    _msg_name = 'Hello'
    def unpack(self, buf):
        self._buf = buf
        self.tlvs = self._parse_tlvs(buf)
        self.data = b''


class EIGRPUpdate(_EIGRPMessageMixin, dpkt.Packet):
    _msg_name = 'Update'
    def unpack(self, buf):
        self._buf = buf
        self.tlvs = self._parse_tlvs(buf)
        self.data = b''


class EIGRPQuery(_EIGRPMessageMixin, dpkt.Packet):
    _msg_name = 'Query'
    def unpack(self, buf):
        self._buf = buf
        self.tlvs = self._parse_tlvs(buf)
        self.data = b''


class EIGRPReply(_EIGRPMessageMixin, dpkt.Packet):
    _msg_name = 'Reply'
    def unpack(self, buf):
        self._buf = buf
        self.tlvs = self._parse_tlvs(buf)
        self.data = b''


class EIGRPSIAQuery(_EIGRPMessageMixin, dpkt.Packet):
    _msg_name = 'SIAQuery'
    def unpack(self, buf):
        self._buf = buf
        self.tlvs = self._parse_tlvs(buf)
        self.data = b''


class EIGRPSIAReply(_EIGRPMessageMixin, dpkt.Packet):
    _msg_name = 'SIAReply'
    def unpack(self, buf):
        self._buf = buf
        self.tlvs = self._parse_tlvs(buf)
        self.data = b''


EIGRP._opcode_sw.update({
    EIGRP_OP_HELLO: EIGRPHello, EIGRP_OP_UPDATE: EIGRPUpdate,
    EIGRP_OP_QUERY: EIGRPQuery, EIGRP_OP_REPLY: EIGRPReply,
    EIGRP_OP_SIAQUERY: EIGRPSIAQuery, EIGRP_OP_SIAREPLY: EIGRPSIAReply,
})


def test_eigrp_header():
    """Parse EIGRP header fields."""
    buf = struct.pack('>BBHIIII', 2, EIGRP_OP_HELLO, 0, 0, 1, 0, 100)
    pkt = EIGRP(buf)
    assert pkt.v == 2
    assert pkt.opcode == EIGRP_OP_HELLO
    assert pkt.asn == 100
    assert len(bytes(pkt)) == 20


def test_eigrp_param_tlv():
    tlv = EIGRPParamTLV(k1=1, k3=1, hold_time=15)
    data = bytes(tlv)
    assert data[0:2] == struct.pack('>H', EIGRP_TLV_PARAM)
    parsed = EIGRPParamTLV(data)
    assert parsed.k3 == 1
    assert parsed.hold_time == 15


def test_eigrp_internal_route():
    tlv = EIGRPInternalRouteTLV()
    tlv.next_hop = 0x0a000001; tlv.delay = 1000; tlv.bandwidth = 100000
    tlv.mtu = 1500; tlv.hop_count = 0; tlv.reliability = 255; tlv.load = 1
    tlv.prefix_length = 24; tlv.prefix = b'\x0a\x00\x00'
    sm = EIGRPScaledMetricTLV()
    sm.scaled_delay = 100; sm.scaled_bandwidth = 1000; sm.type = EIGRP_METRIC_SCALED
    sm.length = 12; sm.value = struct.pack('>II', 100, 1000)
    tlv.metrics = [sm]
    data = bytes(tlv)
    parsed = EIGRPInternalRouteTLV(data)
    assert parsed.prefix_length == 24
    assert len(parsed.metrics) == 1


def test_eigrp_external_route():
    tlv = EIGRPExternalRouteTLV()
    tlv.next_hop = 0x0a000001; tlv.prefix_length = 24; tlv.prefix = b'\x0a\x00\x00'
    tlv.origin_router = 0x0a0000fe; tlv.tag = 100
    data = bytes(tlv)
    parsed = EIGRPExternalRouteTLV(data)
    assert parsed.origin_router == 0x0a0000fe
    assert parsed.tag == 100


def test_eigrp_hello_with_param():
    param = EIGRPParamTLV(k1=1, k3=1, hold_time=15)
    param_bytes = bytes(param)
    hello_body = param_bytes
    buf = struct.pack('>BBHIIII', 2, EIGRP_OP_HELLO, 0, 0, 1, 0, 100) + hello_body
    pkt = EIGRP(buf)
    assert isinstance(pkt.data, EIGRPHello)
    assert len(pkt.hello.tlvs) == 1
    assert isinstance(pkt.hello.tlvs[0], EIGRPParamTLV)


def test_eigrp_ipv6_route():
    tlv = EIGRPInternalRouteTLV()
    tlv.next_hop = 0; tlv.prefix_length = 64
    tlv.prefix = b'\x20\x01\x0d\xb8\x00\x00\x00\x00'
    data = bytes(tlv)
    parsed = EIGRPInternalRouteTLV(data)
    assert parsed.prefix_length == 64
    assert parsed.prefix == b'\x20\x01\x0d\xb8\x00\x00\x00\x00'


def test_eigrp_roundtrip():
    param = EIGRPParamTLV(k1=1, k3=1, hold_time=15)
    param_bytes = bytes(param)
    pkt = EIGRP(v=2, opcode=EIGRP_OP_HELLO, seq=1, asn=100, data=param_bytes)
    data = bytes(pkt)
    parsed = EIGRP(data)
    assert isinstance(parsed.data, EIGRPHello)
    assert len(parsed.hello.tlvs) == 1
    assert parsed.hello.tlvs[0].hold_time == 15
