# -*- coding: utf-8 -*-
"""Intermediate System to Intermediate System."""
from __future__ import absolute_import, print_function
import struct
from . import dpkt

# PDU types
PDU_LAN_L1_HELLO = 1; PDU_LAN_L2_HELLO = 2; PDU_P2P_HELLO = 3
PDU_L1_LSP = 4; PDU_L2_LSP = 5; PDU_L1_CSNP = 6; PDU_L2_CSNP = 7
PDU_L1_PSNP = 8; PDU_L2_PSNP = 9

# TLV types
TLV_AREA_ADDR = 1; TLV_IS_NEIGHBORS = 6; TLV_AUTH = 10
TLV_EIS_REACH = 22; TLV_IP_INT_REACH = 128
TLV_PROTO_SUP = 129; TLV_IP_EXT_REACH = 130


class ISISTLV(object):
    """IS-IS TLV: type(1B) + length(1B) + value(variable)."""
    def __init__(self, buf=None):
        self.type = 0; self.length = 0; self.value = b''
        if buf: self.unpack(buf)

    def unpack(self, buf):
        self.type, self.length = buf[0], buf[1]
        self.value = buf[2:2 + self.length]

    def __bytes__(self):
        return bytes([self.type, len(self.value)]) + self.value

    def __len__(self):
        return 2 + len(self.value)


class ISISGenericTLV(ISISTLV):
    """Fallback TLV for unknown types."""
    pass


class _ISISTLVParser(object):
    def _parse_tlvs(self, buf):
        tlvs = []; off = 0
        while off + 2 <= len(buf):
            t, l = buf[off], buf[off+1]
            if l < 0 or off + 2 + l > len(buf): break
            cls = ISIS._tlv_sw.get(t, ISISGenericTLV)
            tlvs.append(cls(buf[off:off + 2 + l])); off += 2 + l
        return tlvs


class ISIS(dpkt.Packet):
    """IS-IS Protocol Packet."""
    __byte_order__ = '>'
    __hdr__ = (
        ('nlpid', 'B', 0x83),
        ('hdr_len', 'B', 0),
        ('version', 'B', 1),
        ('id_len', 'B', 0),
        ('_pdu_type', 'B', 0),
        ('version2', 'B', 1),
        ('rsvd', 'B', 0),
        ('max_area', 'B', 0),
    )
    _pdu_sw = {}
    _tlv_sw = {}

    @property
    def pdu_type(self):
        return self._pdu_type

    @pdu_type.setter
    def pdu_type(self, v):
        self._pdu_type = v

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        cls = self._pdu_sw.get(self.pdu_type)
        if cls and self.data:
            self.data = cls(self.data)
            setattr(self, self.data._msg, self.data)


class ISISLANHelloL1(_ISISTLVParser, dpkt.Packet):
    _msg = 'lan_hello_l1'
    def unpack(self, buf):
        self.circuit_type = buf[0]; self.source_id = buf[1:7]
        self.hold_time = struct.unpack('>H', buf[7:9])[0]
        self.pdu_len = struct.unpack('>H', buf[9:11])[0]
        self.priority = buf[11]; self.lan_id = buf[12:19]
        self.tlvs = self._parse_tlvs(buf[19:]); self.data = b''

class ISISLANHelloL2(ISISLANHelloL1): _msg = 'lan_hello_l2'

class ISISP2PHello(_ISISTLVParser, dpkt.Packet):
    _msg = 'p2p_hello'
    def unpack(self, buf):
        self.circuit_type = buf[0]; self.source_id = buf[1:7]
        self.hold_time = struct.unpack('>H', buf[7:9])[0]
        self.pdu_len = struct.unpack('>H', buf[9:11])[0]
        self.local_circuit_id = buf[11]
        self.tlvs = self._parse_tlvs(buf[12:]); self.data = b''

class ISISLSPL1(_ISISTLVParser, dpkt.Packet):
    _msg = 'lsp_l1'
    def unpack(self, buf):
        self.pdu_len = struct.unpack('>H', buf[0:2])[0]
        self.remaining_life = struct.unpack('>H', buf[2:4])[0]
        self.lsp_id = buf[4:12]
        self.seq = struct.unpack('>I', buf[12:16])[0]
        self.checksum = struct.unpack('>H', buf[16:18])[0]
        self.tlvs = self._parse_tlvs(buf[19:]); self.data = b''

class ISISLSPL2(ISISLSPL1): _msg = 'lsp_l2'

class ISISCSNPL1(_ISISTLVParser, dpkt.Packet):
    _msg = 'csnp_l1'
    def unpack(self, buf):
        self.pdu_len = struct.unpack('>H', buf[0:2])[0]; self.source_id = buf[2:10]
        self.start_lsp_id = buf[10:18]; self.end_lsp_id = buf[18:26]
        self.tlvs = self._parse_tlvs(buf[26:]); self.data = b''

class ISISCSNPL2(ISISCSNPL1): _msg = 'csnp_l2'

class ISISPSNPL1(_ISISTLVParser, dpkt.Packet):
    _msg = 'psnp_l1'
    def unpack(self, buf):
        self.pdu_len = struct.unpack('>H', buf[0:2])[0]; self.source_id = buf[2:10]
        self.tlvs = self._parse_tlvs(buf[10:]); self.data = b''

class ISISPSNPL2(ISISPSNPL1): _msg = 'psnp_l2'


ISIS._pdu_sw.update({
    PDU_LAN_L1_HELLO: ISISLANHelloL1, PDU_LAN_L2_HELLO: ISISLANHelloL2,
    PDU_P2P_HELLO: ISISP2PHello, PDU_L1_LSP: ISISLSPL1, PDU_L2_LSP: ISISLSPL2,
    PDU_L1_CSNP: ISISCSNPL1, PDU_L2_CSNP: ISISCSNPL2,
    PDU_L1_PSNP: ISISPSNPL1, PDU_L2_PSNP: ISISPSNPL2,
})


class ISISAreaAddrTLV(ISISTLV):
    def unpack(self, buf):
        super().unpack(buf); self.addresses = self.value

class ISISNeighborsTLV(ISISTLV):
    def unpack(self, buf):
        super().unpack(buf); self.neighbors = []; off = 0
        while off + 6 <= len(self.value):
            self.neighbors.append(self.value[off:off+6]); off += 6

class ISISAuthTLV(ISISTLV):
    def unpack(self, buf):
        super().unpack(buf)
        if len(self.value) >= 1:
            self.auth_type = self.value[0]; self.auth_data = self.value[1:]

class ISISEISReachTLV(ISISTLV):
    def unpack(self, buf):
        super().unpack(buf); self.reachabilities = []; off = 0
        while off + 11 <= len(self.value):
            nid = self.value[off:off+7]
            metric = struct.unpack('>I', self.value[off+7:off+7+3]+b'\x00')[0]>>8
            extra = self.value[off+10]
            self.reachabilities.append({'neighbor':nid,'metric':metric,'subtlvs':self.value[off+11:off+11+extra]})
            off += 11 + extra

class ISISIPIntReachTLV(ISISTLV):
    def unpack(self, buf):
        super().unpack(buf); self.prefixes = []; off = 0
        while off + 12 <= len(self.value):
            metric = struct.unpack('>I', self.value[off:off+4])[0]
            ctrl = self.value[off+4]; prefix = self.value[off+5:off+9]
            mask = self.value[off+9:off+13]
            self.prefixes.append({'metric':metric,'ctrl':ctrl,'prefix':prefix,'mask':mask}); off += 12

class ISISProtoSupTLV(ISISTLV):
    def unpack(self, buf):
        super().unpack(buf); self.protocols = self.value

class ISISIPExtReachTLV(ISISIPIntReachTLV): pass


ISIS._tlv_sw.update({
    TLV_AREA_ADDR: ISISAreaAddrTLV, TLV_IS_NEIGHBORS: ISISNeighborsTLV,
    TLV_AUTH: ISISAuthTLV, TLV_EIS_REACH: ISISEISReachTLV,
    TLV_IP_INT_REACH: ISISIPIntReachTLV, TLV_PROTO_SUP: ISISProtoSupTLV,
    TLV_IP_EXT_REACH: ISISIPExtReachTLV,
})


def test_isis_header():
    """Parse IS-IS header fields."""
    buf = struct.pack('>BBBBBBBB', 0x83, 0, 1, 0, PDU_LAN_L1_HELLO, 1, 0, 3)
    pkt = ISIS(buf)
    assert pkt.nlpid == 0x83
    assert pkt.pdu_type == PDU_LAN_L1_HELLO
    assert pkt.max_area == 3


def test_isis_lan_hello():
    buf = struct.pack('>BBBBBBBB', 0x83, 0, 1, 0, PDU_LAN_L1_HELLO, 1, 0, 3)
    body = bytes([1]) + b'\x00'*6 + struct.pack('>HH', 30, 1500) + bytes([64]) + b'\x00'*7
    pkt = ISIS(buf + body)
    assert isinstance(pkt.data, ISISLANHelloL1)
    assert pkt.data.hold_time == 30

def test_isis_lsp():
    buf = struct.pack('>BBBBBBBB', 0x83, 0, 1, 0, PDU_L1_LSP, 1, 0, 3)
    body = struct.pack('>HH', 100, 3600) + b'\x00'*8 + struct.pack('>IH', 0x80000001, 0) + b'\x00'
    pkt = ISIS(buf + body)
    assert isinstance(pkt.data, ISISLSPL1)
    assert pkt.data.remaining_life == 3600

def test_isis_ip_reach():
    tlv = ISISIPIntReachTLV(bytes([TLV_IP_INT_REACH, 12]) +
        struct.pack('>I', 10) + bytes([0]) + b'\x0a\x00\x00\x01' + b'\xff\xff\xff\x00')
    assert len(tlv.prefixes) == 1
    assert tlv.prefixes[0]['metric'] == 10
