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


def test_isis_header():
    """Parse IS-IS header fields."""
    buf = struct.pack('>BBBBBBBB', 0x83, 0, 1, 0, PDU_LAN_L1_HELLO, 1, 0, 3)
    pkt = ISIS(buf)
    assert pkt.nlpid == 0x83
    assert pkt.pdu_type == PDU_LAN_L1_HELLO
    assert pkt.max_area == 3
