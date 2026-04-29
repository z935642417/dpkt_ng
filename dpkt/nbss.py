# -*- coding: utf-8 -*-
"""NetBIOS Session Service."""
from __future__ import print_function
from __future__ import absolute_import

from . import dpkt


class NBSS(dpkt.Packet):
    """NetBIOS Session Service wrapper.

    Attributes:
        __hdr__: NBSS 4-byte header
            type: (int) Message type (0x00 = Session Message)
            _len: (bytes) 24-bit big-endian length
    """
    __hdr__ = (
        ('type', 'B', 0),
        ('_len', '3s', b'\x00' * 3),
    )

    @property
    def length(self):
        return (self._len[0] << 16) | (self._len[1] << 8) | self._len[2]

    @length.setter
    def length(self, v):
        self._len = bytes([(v >> 16) & 0xFF, (v >> 8) & 0xFF, v & 0xFF])

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        self.data = buf[self.__hdr_len__:self.__hdr_len__ + self.length]


def test_nbss():
    """Test NBSS header parsing."""
    buf = b'\x00\x00\x00\x2a\xffSMB' + b'\x00' * 38
    nbss = NBSS(buf)
    assert nbss.type == 0x00
    assert nbss.length == 42
    assert len(nbss.data) == 42
    assert nbss.data[0:4] == b'\xffSMB'


def test_nbss_roundtrip():
    """Test NBSS construct -> bytes -> parse."""
    payload = b'\xffSMB' + b'\x00' * 28
    nbss = NBSS(type=0, data=payload)
    nbss.length = len(payload)
    data = bytes(nbss)
    assert len(data) == 4 + len(payload)
    parsed = NBSS(data)
    assert parsed.length == len(payload)
    assert parsed.data == payload


if __name__ == '__main__':
    test_nbss()
    test_nbss_roundtrip()
    print('All tests passed.')
