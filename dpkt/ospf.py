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
    __hdr__ = OSPF.__hdr__ + (
        ('atype', 'H', AUTH_NONE),
        ('auth', '8s', b''),
    )
    _msg_sw = {}

    def __init__(self, *args, **kwargs):
        super(OSPFv2, self).__init__(*args, **kwargs)
        if not args:
            self.v = OSPF_VERSION_2

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        cls = self._msg_sw.get(self.type)
        if cls and self.data:
            self.data = cls(self.data)
            setattr(self, self.data.__class__.__name__.split('v2', 1)[-1].lower(), self.data)


class OSPFv3(OSPF):
    pass


class OSPFv2Hello(dpkt.Packet):
    """OSPFv2 Hello packet."""
    __hdr__ = (
        ('mask', 'I', 0),
        ('hello_interval', 'H', 10),
        ('opts', 'B', 0),
        ('router_priority', 'B', 0),
        ('dead_interval', 'I', 40),
        ('designated_router', 'I', 0),
        ('backup_designated_router', 'I', 0),
    )

    def __init__(self, *args, **kwargs):
        self.neighbors = []
        super(OSPFv2Hello, self).__init__(*args, **kwargs)

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        self.neighbors = []
        off = self.__hdr_len__
        while off + 4 <= len(buf):
            self.neighbors.append(struct.unpack('>I', buf[off:off + 4])[0])
            off += 4
        self.data = b''

    def __bytes__(self):
        hdr = self.pack_hdr()
        for n in self.neighbors:
            hdr += struct.pack('>I', n)
        return hdr

    def __len__(self):
        return self.__hdr_len__ + 4 * len(self.neighbors)


class OSPFv2DBD(dpkt.Packet):
    """OSPFv2 Database Description packet."""
    __hdr__ = (
        ('mtu', 'H', 0),
        ('opts', 'B', 0),
        ('flags', 'B', 0),
        ('seq', 'I', 0),
    )


class OSPFv2LSR(dpkt.Packet):
    """OSPFv2 Link State Request."""
    def __init__(self, *args, **kwargs):
        self.requests = []
        super(OSPFv2LSR, self).__init__(*args, **kwargs)

    def unpack(self, buf):
        self.requests = []
        off = 0
        while off + 12 <= len(buf):
            ls_type = struct.unpack('>I', buf[off:off + 4])[0]
            ls_id = struct.unpack('>I', buf[off + 4:off + 8])[0]
            adv_router = struct.unpack('>I', buf[off + 8:off + 12])[0]
            self.requests.append({'type': ls_type, 'id': ls_id, 'adv_router': adv_router})
            off += 12
        self.data = b''

    def __bytes__(self):
        result = b''
        for r in self.requests:
            result += struct.pack('>III', r['type'], r['id'], r['adv_router'])
        return result

    def __len__(self):
        return 12 * len(self.requests)


class OSPFv2LSU(dpkt.Packet):
    """OSPFv2 Link State Update."""
    _lsa_sw = {}

    def __init__(self, *args, **kwargs):
        self.lsas = []
        super(OSPFv2LSU, self).__init__(*args, **kwargs)

    def unpack(self, buf):
        self.lsa_count = struct.unpack('>I', buf[:4])[0]
        off = 4
        self.lsas = []
        for _ in range(self.lsa_count):
            if off + 20 > len(buf):
                break
            lsa_len = struct.unpack('>H', buf[off + 18:off + 20])[0]
            lsa_buf = buf[off:off + lsa_len]
            lsa_type = struct.unpack('>B', lsa_buf[2:3])[0]
            cls = self._lsa_sw.get(lsa_type, LSAv2Header)
            try:
                lsa = cls(lsa_buf)
            except (dpkt.UnpackError, struct.error):
                lsa = LSAv2Header(lsa_buf)
            self.lsas.append(lsa)
            off += lsa_len
        self.data = b''

    def __bytes__(self):
        hdr = struct.pack('>I', len(self.lsas))
        for lsa in self.lsas:
            hdr += bytes(lsa)
        return hdr

    def __len__(self):
        return 4 + sum(len(bytes(lsa)) for lsa in self.lsas)


class OSPFv2LSAck(dpkt.Packet):
    """OSPFv2 Link State Acknowledgment."""
    def __init__(self, *args, **kwargs):
        self.lsa_headers = []
        super(OSPFv2LSAck, self).__init__(*args, **kwargs)

    def unpack(self, buf):
        self.lsa_headers = []
        off = 0
        while off + 20 <= len(buf):
            lsa = LSAv2Header(buf[off:off + 20])
            self.lsa_headers.append(lsa)
            off += 20
        self.data = b''

    def __bytes__(self):
        return b''.join(bytes(h) for h in self.lsa_headers)

    def __len__(self):
        return 20 * len(self.lsa_headers)


class LSAv2Header(dpkt.Packet):
    """OSPFv2 LSA common header (20 bytes)."""
    __hdr__ = (
        ('age', 'H', 0),
        ('opts', 'B', 0),
        ('type', 'B', 0),
        ('id', 'I', 0),
        ('adv_router', 'I', 0),
        ('seq', 'I', 0),
        ('sum', 'H', 0),
        ('len', 'H', 20),
    )


class LSARouter(LSAv2Header):
    """OSPFv2 Router-LSA."""
    def __init__(self, *args, **kwargs):
        self.links = []
        super(LSARouter, self).__init__(*args, **kwargs)

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        flags, rsv, link_count = struct.unpack('>BBH', self.data[:4])
        self.flags = flags
        self.links = []
        off = 4
        for _ in range(link_count):
            if off + 12 > len(self.data):
                break
            link = struct.unpack('>IIBBH', self.data[off:off + 12])
            self.links.append({'id': link[0], 'data': link[1], 'type': link[2],
                               'tos': link[3], 'metric': link[4]})
            off += 12
        self.data = b''

    def __bytes__(self):
        hdr = self.pack_hdr()
        body = struct.pack('>BBH', self.flags, 0, len(self.links))
        for link in self.links:
            body += struct.pack('>IIBBH', link['id'], link['data'],
                               link['type'], link['tos'], link['metric'])
        return hdr + body

    def __len__(self):
        return self.__hdr_len__ + 4 + 12 * len(self.links)


class LSANetwork(LSAv2Header):
    """OSPFv2 Network-LSA."""
    def __init__(self, *args, **kwargs):
        self.routers = []
        super(LSANetwork, self).__init__(*args, **kwargs)

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        self.mask = struct.unpack('>I', self.data[:4])[0]
        self.routers = []
        off = 4
        while off + 4 <= len(self.data):
            self.routers.append(struct.unpack('>I', self.data[off:off + 4])[0])
            off += 4
        self.data = b''

    def __bytes__(self):
        hdr = self.pack_hdr()
        body = struct.pack('>I', self.mask)
        for r in self.routers:
            body += struct.pack('>I', r)
        return hdr + body

    def __len__(self):
        return self.__hdr_len__ + 4 + 4 * len(self.routers)


class LSASummaryIP(LSAv2Header):
    """OSPFv2 Summary-IP (type 3) LSA."""
    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        self.mask = struct.unpack('>I', self.data[:4])[0]
        metric = self.data[4:7] + b'\x00'
        self.metric = struct.unpack('>I', metric)[0] >> 8
        self.data = b''

    def __bytes__(self):
        hdr = self.pack_hdr()
        body = struct.pack('>I', self.mask) + struct.pack('>I', self.metric << 8)[:3]
        return hdr + body

    def __len__(self):
        return self.__hdr_len__ + 7


class LSASummaryASBR(LSASummaryIP):
    """OSPFv2 ASBR-Summary (type 4) LSA."""
    pass


class LSAASExternal(LSASummaryIP):
    """OSPFv2 AS-External (type 5) LSA."""
    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        self.mask = struct.unpack('>I', self.data[:4])[0]
        self.flags = self.data[4]
        metric = self.data[5:8] + b'\x00'
        self.metric = struct.unpack('>I', metric)[0] >> 8
        if len(self.data) >= 16:
            self.forwarding = struct.unpack('>I', self.data[8:12])[0]
            self.tag = struct.unpack('>I', self.data[12:16])[0]
        else:
            self.forwarding = 0
            self.tag = 0
        self.data = b''

    def __bytes__(self):
        hdr = self.pack_hdr()
        body = struct.pack('>I', self.mask) + bytes([self.flags])
        body += struct.pack('>I', self.metric << 8)[:3]
        body += struct.pack('>II', self.forwarding, self.tag)
        return hdr + body

    def __len__(self):
        return self.__hdr_len__ + 16


# Register v2 LSA types
OSPFv2LSU._lsa_sw.update({
    LSAv2_ROUTER: LSARouter,
    LSAv2_NETWORK: LSANetwork,
    LSAv2_SUMMARY_IP: LSASummaryIP,
    LSAv2_SUMMARY_ASBR: LSASummaryASBR,
    LSAv2_AS_EXTERNAL: LSAASExternal,
})

# Register v2 message types
OSPFv2._msg_sw.update({
    OSPF_MSG_HELLO: OSPFv2Hello,
    OSPF_MSG_DBD: OSPFv2DBD,
    OSPF_MSG_LSR: OSPFv2LSR,
    OSPF_MSG_LSU: OSPFv2LSU,
    OSPF_MSG_LSACK: OSPFv2LSAck,
})


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
    buf = b'\x02\x01\x00\x18\xc0\xa8\x01\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    pkt = OSPF(buf)
    assert isinstance(pkt, OSPFv2)
    assert pkt.v == 2

def test_ospf_factory_v3():
    """OSPF(buf) with v=3 returns OSPFv3 instance."""
    buf = b'\x03\x01\x00\x14\xc0\xa8\x01\x01\x00\x00\x00\x01\x00\x00\x00\x00'
    pkt = OSPF(buf)
    assert isinstance(pkt, OSPFv3)
    assert pkt.v == 3

def test_ospf_v2_hello():
    """OSPFv2 Hello with mask, interval, neighbors roundtrip."""
    hello = OSPFv2Hello(mask=0xffffff00, hello_interval=10, router_priority=1,
                        designated_router=0x0a000001,
                        neighbors=[0x0a000002, 0x0a000003])
    ospf = OSPFv2(type=OSPF_MSG_HELLO, router=0x0a000001, area=0, data=hello)
    data = bytes(ospf)
    assert data[0:1] == b'\x02'
    assert data[1:2] == b'\x01'
    parsed = OSPF(data)
    assert isinstance(parsed, OSPFv2)
    assert isinstance(parsed.data, OSPFv2Hello)
    assert parsed.hello.mask == 0xffffff00
    assert len(parsed.hello.neighbors) == 2

def test_ospf_v2_lsu_with_lsa():
    """OSPFv2 LSU containing LSA header."""
    router_lsa = LSAv2Header(type=LSAv2_ROUTER, id=0x0a000001,
                             adv_router=0x0a000001, seq=0x80000001, len=20)
    lsu = OSPFv2LSU(lsas=[router_lsa])
    ospf = OSPFv2(type=OSPF_MSG_LSU, router=0x0a000001, area=0, data=lsu)
    data = bytes(ospf)
    parsed = OSPF(data)
    assert isinstance(parsed, OSPFv2)
    assert isinstance(parsed.data, OSPFv2LSU)
    assert len(parsed.lsu.lsas) == 1
    assert parsed.lsu.lsas[0].type == LSAv2_ROUTER

def test_ospf_v2_router_lsa():
    """Router-LSA with link list roundtrip."""
    lsa = LSARouter(type=LSAv2_ROUTER, id=0x0a000001, adv_router=0x0a000001,
                    flags=0, links=[{'id': 0x0a000002, 'data': 0x0a000002,
                                     'type': 2, 'tos': 0, 'metric': 10}])
    data = bytes(lsa)
    parsed = LSARouter(data)
    assert len(parsed.links) == 1
    assert parsed.links[0]['metric'] == 10
    assert parsed.links[0]['type'] == 2
