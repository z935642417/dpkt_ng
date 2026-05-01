# -*- coding: utf-8 -*-
"""Virtual eXtensible Local Area Network (RFC 7348)."""
from __future__ import absolute_import, print_function
import struct
from . import dpkt


class VXLAN(dpkt.Packet):
    """VXLAN encapsulation (8-byte header + inner Ethernet frame).

    Attributes:
        flags: (int) Flags byte. I-bit (bit 3) must be 1.
        vni: (int) 24-bit VXLAN Network Identifier.
        data: (bytes) Inner Ethernet frame.
    """
    __byte_order__ = '>'

    def __init__(self, *args, **kwargs):
        self.flags = 0x08
        self.vni = 0
        self._valid = True
        super(VXLAN, self).__init__(*args, **kwargs)

    def unpack(self, buf):
        if len(buf) < 8:
            raise dpkt.NeedData('VXLAN header too short')
        self.flags = buf[0]
        # I-bit (bit 3) must be set per RFC 7348
        if not (self.flags & 0x08):
            self._valid = False
        # Reserved bytes 1-3 must be zero
        if buf[1:4] != b'\x00\x00\x00':
            self._valid = False
        # VNI is 24 bits at bytes 4-6
        self.vni = (buf[4] << 16) | (buf[5] << 8) | buf[6]
        # Reserved2 byte 7 must be zero
        if buf[7] != 0:
            self._valid = False
        self.data = buf[8:]

    def __bytes__(self):
        vni_bytes = struct.pack('>I', self.vni)[1:]  # 24-bit, drop MSB
        header = bytes([self.flags]) + b'\x00' * 3 + vni_bytes + b'\x00'
        return header + bytes(self.data)

    def __len__(self):
        return 8 + len(self.data)

    def __repr__(self):
        status = '' if self._valid else ' [INVALID]'
        return 'VXLAN(vni=%d%s)' % (self.vni, status)

    @property
    def is_valid(self):
        """Check if I-bit set and reserved fields are zero."""
        return self._valid


def test_vxlan_basic():
    """Basic VXLAN header with VNI=100."""
    buf = b'\x08' + b'\x00' * 3 + bytes([0, 0, 100]) + b'\x00' + b'\x00' * 14
    vxlan = VXLAN(buf)
    assert vxlan.vni == 100
    assert vxlan.is_valid
    assert vxlan.flags == 0x08
    assert len(vxlan.data) == 14
    # roundtrip
    assert bytes(vxlan) == buf

def test_vxlan_inner_ethernet():
    """Inner Ethernet frame can be recursively parsed."""
    from . import ethernet
    inner_eth = b'\xff' * 6 + b'\x00' * 6 + b'\x08\x00' + b'\x00' * 46  # min eth frame
    buf = b'\x08' + b'\x00' * 3 + struct.pack('>I', 200)[1:] + b'\x00' + inner_eth
    vxlan = VXLAN(buf)
    assert vxlan.vni == 200
    eth = ethernet.Ethernet(vxlan.data)
    assert isinstance(eth, ethernet.Ethernet)
    assert eth.type == 0x0800  # IPv4

def test_vxlan_invalid_ibit():
    """I-bit=0 should mark packet as invalid."""
    buf = b'\x00' + b'\x00' * 3 + bytes([0, 0, 1]) + b'\x00' + b'\x00'
    vxlan = VXLAN(buf)
    assert not vxlan.is_valid
    assert vxlan.vni == 1  # VNI still parsed

def test_vxlan_invalid_reserved():
    """Non-zero reserved should mark invalid."""
    buf = b'\x08' + b'\x01' + b'\x00' * 2 + bytes([0, 0, 1]) + b'\x00' + b'\x00'
    vxlan = VXLAN(buf)
    assert not vxlan.is_valid
