# -*- coding: utf-8 -*-
"""GPRS Tunneling Protocol (GTPv1/GTPv2)."""
from __future__ import absolute_import, print_function
import struct
from . import dpkt
from .compat import compat_ord

# ---- GTPv1 Message Types ----
GTPV1_ECHO_REQ = 1
GTPV1_ECHO_RESP = 2
GTPV1_CREATE_PDP_REQ = 16
GTPV1_CREATE_PDP_RESP = 17
GTPV1_UPDATE_PDP_REQ = 18
GTPV1_UPDATE_PDP_RESP = 19
GTPV1_DELETE_PDP_REQ = 20
GTPV1_DELETE_PDP_RESP = 21
GTPV1_ERROR_IND = 26
GTPV1_GPDU = 255

# ---- GTPv2 Message Types ----
GTPV2_ECHO_REQ = 1
GTPV2_ECHO_RESP = 2
GTPV2_CREATE_SESSION_REQ = 32
GTPV2_CREATE_SESSION_RESP = 33
GTPV2_MODIFY_BEARER_REQ = 34
GTPV2_MODIFY_BEARER_RESP = 35
GTPV2_DELETE_SESSION_REQ = 36
GTPV2_DELETE_SESSION_RESP = 37

# ---- IE Types ----
IE_IMSI = 1
IE_APN = 71
IE_BEARER_CTX = 93
IE_PDN_TYPE = 99
IE_UE_TIMEZONE = 114
IE_FTEID = 87
IE_AMBR = 72
IE_RAT_TYPE = 82

# GTPv1 flag bits (in _flags_msg byte)
GTPV1_F_S = 0x02   # Sequence Number present
GTPV1_F_PN = 0x01  # N-PDU Number present
GTPV1_F_E = 0x04   # Extension Header present
GTPV1_F_PT = 0x10  # Protocol Type (1=GTP-C, 0=GTP-U)


# ---- IE Framework ----
class GTPIE(object):
    """Base IE: type(1B) + length(1B v1 or 2B v2) + value."""
    def __init__(self, buf=None, v2_length=False):
        self.type = 0
        self.length = 0
        self.value = b''
        self._v2 = v2_length
        if buf:
            self.unpack(buf)

    def unpack(self, buf):
        self.type = buf[0]
        if self._v2:
            self.length = struct.unpack('>H', buf[1:3])[0]
            self.value = buf[3:3 + self.length]
        else:
            self.length = compat_ord(buf[1])
            self.value = buf[2:2 + self.length]

    def __len__(self):
        hdr = 3 if self._v2 else 2
        return hdr + len(self.value)

    def __bytes__(self):
        if self._v2:
            return struct.pack('>BH', self.type, self.length) + self.value
        return struct.pack('>BB', self.type, self.length) + self.value

    def __repr__(self):
        return '{cls}(type={t}, length={l}, value={v!r})'.format(
            cls=self.__class__.__name__, t=self.type, l=self.length, v=self.value)


class GTPGenericIE(GTPIE):
    pass


class GTPIMSIIE(GTPIE):
    def unpack(self, buf):
        GTPIE.unpack(self, buf)
        if self.value:
            self.imsi = self.value


class GTPAPNIE(GTPIE):
    def unpack(self, buf):
        GTPIE.unpack(self, buf)
        self.apn = self.value


class GTPFTEIDIE(GTPIE):
    def unpack(self, buf):
        GTPIE.unpack(self, buf)
        if len(self.value) >= 9:
            flags = compat_ord(self.value[0])
            self.iface = flags & 0x1f
            self.v4 = (flags >> 5) & 1
            self.v6 = (flags >> 6) & 1
            self.teid = struct.unpack('>I', self.value[1:5])[0]
            pos = 5
            v4_addr_len = 4 if self.v4 else 0
            v6_addr_len = 16 if self.v6 else 0
            self.ipv4 = self.value[pos:pos + v4_addr_len] if v4_addr_len else b''
            self.ipv6 = self.value[pos + v4_addr_len:pos + v4_addr_len + v6_addr_len] if v6_addr_len else b''


class GTPPDNTypeIE(GTPIE):
    def unpack(self, buf):
        GTPIE.unpack(self, buf)
        if self.value:
            self.pdn_type = compat_ord(self.value[0])


class GTPAMBR_IE(GTPIE):
    def unpack(self, buf):
        GTPIE.unpack(self, buf)
        if len(self.value) >= 8:
            self.uplink = struct.unpack('>I', self.value[0:4])[0]
            self.downlink = struct.unpack('>I', self.value[4:8])[0]


# IE dispatch tables
_v1_ie_sw = {
    IE_IMSI: GTPIMSIIE,
    IE_APN: GTPAPNIE,
    IE_PDN_TYPE: GTPPDNTypeIE,
    IE_AMBR: GTPAMBR_IE,
    IE_FTEID: GTPFTEIDIE,
}
_v2_ie_sw = {
    IE_IMSI: GTPIMSIIE,
    IE_APN: GTPAPNIE,
    IE_PDN_TYPE: GTPPDNTypeIE,
    IE_FTEID: GTPFTEIDIE,
    IE_AMBR: GTPAMBR_IE,
    IE_BEARER_CTX: GTPGenericIE,
}


def parse_ies(buf, v2=False):
    """Parse IE list from buffer."""
    ies = []
    off = 0
    while off < len(buf):
        ie_type = compat_ord(buf[off])
        cls = (_v2_ie_sw if v2 else _v1_ie_sw).get(ie_type, GTPGenericIE)
        ie = cls(buf[off:], v2_length=v2)
        ies.append(ie)
        # v2: type(1) + length(2) + value(length) = 3 + ie.length
        # v1: type(1) + length(1) + value(length) = 2 + ie.length
        hdr = 3 if v2 else 2
        off += ie.length + hdr
    return ies


# ---- GTP Header ----
class GTP(dpkt.Packet):
    """GTP base with auto-detection of version."""
    __byte_order__ = '>'

    def __new__(cls, *args, **kwargs):
        if args and isinstance(args[0], (bytes, bytearray)):
            buf = args[0]
            if len(buf) >= 1:
                ver = compat_ord(buf[0]) >> 5 & 7
                if ver == 2:
                    return object.__new__(GTPv2)
                elif ver == 1:
                    return object.__new__(GTPv1)
        return object.__new__(cls)


class GTPv1(GTP):
    """GTPv1 header (v1-C and v1-U).

    GTPv1 header format (3GPP TS 29.060):
        Octets 1:  Version(3) | PT(1) | Spare(1) | E(1) | S(1) | PN(1)
        Octets 2:  Message Type
        Octets 3-4: Length (payload after mandatory 8-octet header)
        Octets 5-8: Tunnel Endpoint Identifier (TEID)
        Optional:
          Sequence Number (2B) if S=1
          N-PDU Number (1B)  if PN=1
          Next Extension Header Type (1B) if E=1
    """
    __hdr__ = (
        ('_flags_msg', 'B', 0x30),
        ('type', 'B', 0),
        ('length', 'H', 0),
        ('teid', 'I', 0),
    )
    __bit_fields__ = {
        '_flags_msg': (
            ('_ver', 3),
            ('_pt', 1),
            ('_rsv1', 1),
            ('_e', 1),
            ('_s', 1),
            ('_pn', 1),
        ),
    }

    @property
    def version(self):
        return self._flags_msg >> 5

    @property
    def is_control(self):
        return bool(self._flags_msg & GTPV1_F_PT)

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        flags = self._flags_msg
        off = 0
        if flags & GTPV1_F_S:
            self.seq = struct.unpack('>H', self.data[off:off + 2])[0]
            off += 2
        if flags & GTPV1_F_PN:
            self.npdu = compat_ord(self.data[off])
            off += 1
        if flags & GTPV1_F_E:
            self.next_ext = compat_ord(self.data[off])
            off += 1
        if self.is_control:
            self.ies = parse_ies(self.data[off:], v2=False)
        else:
            self.data = self.data[off:]

    def __len__(self):
        flags = self._flags_msg
        opt_len = 0
        if flags & GTPV1_F_S:
            opt_len += 2
        if flags & GTPV1_F_PN:
            opt_len += 1
        if flags & GTPV1_F_E:
            opt_len += 1
        return self.__hdr_len__ + opt_len + len(self.data)

    def __bytes__(self):
        flags = self._flags_msg
        hdr = self.pack_hdr()
        opt = b''
        if flags & GTPV1_F_S:
            opt += struct.pack('>H', getattr(self, 'seq', 0))
        if flags & GTPV1_F_PN:
            opt += struct.pack('>B', getattr(self, 'npdu', 0))
        if flags & GTPV1_F_E:
            opt += struct.pack('>B', getattr(self, 'next_ext', 0))
        return hdr + opt + bytes(self.data)


class GTPv2(GTP):
    """GTPv2-C header.

    GTPv2 header format (3GPP TS 29.274):
        Octets 1:    Version(3) | P(1) | T(1) | Spare(3)
        Octets 2:    Message Type
        Octets 3-4:  Length (excludes first 4 octets)
        Octets 5-8:  TEID
        Octets 9-11: Sequence Number
        Octets 12:   Spare
    """
    __hdr__ = (
        ('_flags_msg', 'B', 0x48),
        ('type', 'B', 0),
        ('length', 'H', 0),
        ('teid', 'I', 0),
        ('_seq', '3s', b'\x00' * 3),
        ('_spare', 'B', 0),
    )
    __bit_fields__ = {
        '_flags_msg': (
            ('_ver', 3),
            ('_p', 1),
            ('_t', 1),
            ('_spare_bits', 3),
        ),
    }

    @property
    def version(self):
        return self._flags_msg >> 5

    @property
    def sequence(self):
        return (compat_ord(self._seq[0]) << 16) | \
               (compat_ord(self._seq[1]) << 8) | \
               compat_ord(self._seq[2])

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        self.ies = parse_ies(self.data, v2=True)
        self.data = b''

    def __len__(self):
        ie_data = b''.join(bytes(ie) for ie in getattr(self, 'ies', []))
        return self.__hdr_len__ + len(ie_data)

    def __bytes__(self):
        ie_data = b''.join(bytes(ie) for ie in getattr(self, 'ies', []))
        return self.pack_hdr() + ie_data


# ---- Tests ----
def test_gtp_v1_echo():
    """GTPv1 Echo Request."""
    # 0x30 = ver 1, PT=1 (control), S=0, PN=0, E=0
    buf = struct.pack('>BBH', 0x30, GTPV1_ECHO_REQ, 0) + struct.pack('>I', 0)
    pkt = GTP(buf)
    assert isinstance(pkt, GTPv1)
    assert pkt.type == GTPV1_ECHO_REQ
    assert pkt.is_control


def test_gtp_v1_user_plane():
    """GTPv1-U with T-PDU."""
    # 0x20 = ver 1, PT=0 (user plane), S=0, PN=0, E=0
    buf = struct.pack('>BBHI', 0x20, GTPV1_GPDU, 4, 0x12345678) + b'IPPKT'
    pkt = GTP(buf)
    assert isinstance(pkt, GTPv1)
    assert not pkt.is_control
    assert pkt.teid == 0x12345678
    assert pkt.data == b'IPPKT'


def test_gtp_v2_create_session():
    """GTPv2 Create Session Request with IE."""
    hdr = struct.pack('>BBHI3sB', 0x48, GTPV2_CREATE_SESSION_REQ, 0,
                      0x9ABCDEF0, b'\x01\x02\x03', 0)
    # FTEID IE: type(1) + len(2) + value(iface|teid|ipv4)
    ie = bytes([IE_FTEID]) + struct.pack('>H', 9) + bytes([0x01]) + \
        struct.pack('>I', 0x12345678) + b'\x0a\x00\x00\x01'
    pkt = GTP(hdr + ie)
    assert isinstance(pkt, GTPv2)
    assert pkt.type == GTPV2_CREATE_SESSION_REQ
    assert pkt.teid == 0x9ABCDEF0
    assert len(pkt.ies) >= 1


def test_gtp_ie_imsi():
    """IMSI IE parsing."""
    ie = GTPIMSIIE(bytes([IE_IMSI, 8]) + b'\x21\x43\x65\x87\x09\x21\x43\xf5',
                   v2_length=False)
    assert ie.type == IE_IMSI
