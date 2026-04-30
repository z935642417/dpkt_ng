# -*- coding: utf-8 -*-
"""Open Shortest Path First."""
from __future__ import absolute_import
from __future__ import print_function

import struct

from . import dpkt

# Auth types
AUTH_NONE = 0
AUTH_PASSWORD = 1
AUTH_CRYPTO = 2

# Versions
OSPF_VERSION_2 = 2
OSPF_VERSION_3 = 3

# Message types
OSPF_MSG_HELLO = 1
OSPF_MSG_DBD = 2
OSPF_MSG_LSR = 3
OSPF_MSG_LSU = 4
OSPF_MSG_LSACK = 5

# LSA types - OSPFv2
LSAv2_ROUTER = 1
LSAv2_NETWORK = 2
LSAv2_SUMMARY_IP = 3
LSAv2_SUMMARY_ASBR = 4
LSAv2_AS_EXTERNAL = 5

# LSA types - OSPFv3
LSAv3_ROUTER = 0x2001
LSAv3_NETWORK = 0x2002
LSAv3_INTER_AREA_PREFIX = 0x2003
LSAv3_INTER_AREA_ROUTER = 0x2004
LSAv3_AS_EXTERNAL = 0x4005
LSAv3_NSSA = 0x2007
LSAv3_LINK = 0x0008
LSAv3_INTRA_AREA_PREFIX = 0x2009


class OSPF(dpkt.Packet):
    """Open Shortest Path First base class."""
    __hdr__ = (
        ('v', 'B', 0),
        ('type', 'B', 0),
        ('len', 'H', 0),
        ('router', 'I', 0),
        ('area', 'I', 0),
        ('sum', 'H', 0),
    )

    def __new__(cls, *args, **kwargs):
        if args and isinstance(args[0], (bytes, bytearray)):
            buf = args[0]
            if len(buf) >= 1:
                v = buf[0] if isinstance(buf[0], int) else buf[0]
                if v == 3:
                    return super(OSPF, cls).__new__(OSPFv3)
                elif v == 2:
                    return super(OSPF, cls).__new__(OSPFv2)
        return super(OSPF, cls).__new__(cls)

    def __bytes__(self):
        if not self.sum:
            self.sum = dpkt.in_cksum(dpkt.Packet.__bytes__(self))
        return dpkt.Packet.__bytes__(self)


class OSPFv2(OSPF):
    pass


class OSPFv3(OSPF):
    pass


def test_ospf_base():
    """OSPF() with no args creates base instance with checksum auto-calc."""
    ospf = OSPF()
    assert ospf.v == 0
    assert ospf.type == 0
    assert ospf.len == 0
    assert ospf.router == 0
    assert ospf.area == 0
    assert ospf.sum == 0
    assert len(bytes(ospf)) == 14

def test_ospf_factory_v2():
    """OSPF(buf) with v=2 returns OSPFv2 instance."""
    buf = b'\x02\x01\x00\x1c\xc0\xa8\x01\x01\x00\x00\x00\x01\x00\x00\x00\x00'
    pkt = OSPF(buf)
    assert isinstance(pkt, OSPFv2)
    assert pkt.v == 2

def test_ospf_factory_v3():
    """OSPF(buf) with v=3 returns OSPFv3 instance."""
    buf = b'\x03\x01\x00\x14\xc0\xa8\x01\x01\x00\x00\x00\x01\x00\x00\x00\x00'
    pkt = OSPF(buf)
    assert isinstance(pkt, OSPFv3)
    assert pkt.v == 3
