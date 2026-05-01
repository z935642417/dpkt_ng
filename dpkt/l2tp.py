# -*- coding: utf-8 -*-
"""Layer 2 Tunneling Protocol (RFC 2661, RFC 3931)."""
from __future__ import absolute_import, print_function
import struct
from . import dpkt

# Control message types (in AVP 0)
L2TP_MSG_SCCRQ = 1
L2TP_MSG_SCCRP = 2
L2TP_MSG_SCCCN = 3
L2TP_MSG_STOPCCN = 4
L2TP_MSG_HELLO = 6
L2TP_MSG_OCRQ = 7
L2TP_MSG_OCRP = 8
L2TP_MSG_OCCN = 9
L2TP_MSG_ICRQ = 10
L2TP_MSG_ICRP = 11
L2TP_MSG_ICCN = 12
L2TP_MSG_CDN = 14
L2TP_MSG_WEN = 15
L2TP_MSG_SLI = 16

# AVP types
AVP_MSG_TYPE = 0
AVP_RESULT_CODE = 1
AVP_PROTO_VER = 2
AVP_FRAMING_CAP = 3
AVP_BEARER_CAP = 4
AVP_TIE_BREAKER = 5
AVP_FIRMWARE_REV = 6
AVP_HOST_NAME = 7
AVP_VENDOR_NAME = 8
AVP_ASSIGNED_TUNNEL = 9
AVP_RECEIVE_WINDOW = 10
AVP_CHALLENGE = 11
AVP_CHALLENGE_RESP = 13
AVP_ASSIGNED_SESSION = 14
AVP_CALL_SERIAL = 15
AVP_CALLING_NUMBER = 22
AVP_CTRL_MSG = 0x3c  # Vendor-Specific marker used as sentinel for generic

RESULT_OK = 1
RESULT_ERROR = 2


# ---- L2TP AVP Framework ----
class L2TPAVP(object):
    """Base AVP: M(1b)+H(1b)+rsvd(4b)+len(2B)+vendor(2B)+type(2B)+value."""
    def __init__(self, buf=None):
        self.m = 0
        self.h = 0
        self.length = 6
        self.vendor = 0
        self.type = 0
        self.value = b''
        if buf:
            self.unpack(buf)

    def unpack(self, buf):
        flags = struct.unpack('>H', buf[0:2])[0]
        self.m = (flags >> 15) & 1
        self.h = (flags >> 14) & 1
        self.length = flags & 0x3ff
        self.vendor = struct.unpack('>H', buf[2:4])[0]
        self.type = struct.unpack('>H', buf[4:6])[0]
        self.value = buf[6:self.length] if self.length >= 6 else b''

    def __bytes__(self):
        flags = (self.m << 15) | (self.h << 14) | (self.length & 0x3ff)
        return struct.pack('>HHH', flags, self.vendor, self.type) + self.value

    def __len__(self):
        return self.length


class L2TPGenericAVP(L2TPAVP):
    pass


# Typed AVP subclasses
class L2TPMsgTypeAVP(L2TPAVP):
    def unpack(self, buf):
        super(L2TPMsgTypeAVP, self).unpack(buf)
        if len(self.value) >= 2:
            self.msg_type = struct.unpack('>H', self.value[0:2])[0]


class L2TPResultCodeAVP(L2TPAVP):
    def unpack(self, buf):
        super(L2TPResultCodeAVP, self).unpack(buf)
        if len(self.value) >= 4:
            self.result = struct.unpack('>H', self.value[0:2])[0]


class L2TPProtoVerAVP(L2TPAVP):
    def unpack(self, buf):
        super(L2TPProtoVerAVP, self).unpack(buf)
        if len(self.value) >= 2:
            self.version = struct.unpack('>H', self.value[0:2])[0]


class L2TPAssignedTunnelAVP(L2TPAVP):
    def unpack(self, buf):
        super(L2TPAssignedTunnelAVP, self).unpack(buf)
        if len(self.value) >= 2:
            self.tunnel_id = struct.unpack('>H', self.value[0:2])[0]


class L2TPAssignedSessionAVP(L2TPAVP):
    def unpack(self, buf):
        super(L2TPAssignedSessionAVP, self).unpack(buf)
        if len(self.value) >= 2:
            self.session_id = struct.unpack('>H', self.value[0:2])[0]


class L2TPCallSerialAVP(L2TPAVP):
    def unpack(self, buf):
        super(L2TPCallSerialAVP, self).unpack(buf)
        if len(self.value) >= 4:
            self.serial = struct.unpack('>I', self.value[0:4])[0]


class L2TPHostNameAVP(L2TPAVP):
    def unpack(self, buf):
        super(L2TPHostNameAVP, self).unpack(buf)
        self.hostname = self.value


class L2TPVendorNameAVP(L2TPAVP):
    def unpack(self, buf):
        super(L2TPVendorNameAVP, self).unpack(buf)
        self.vendor_name = self.value


class L2TPFramingCapAVP(L2TPAVP):
    def unpack(self, buf):
        super(L2TPFramingCapAVP, self).unpack(buf)
        if len(self.value) >= 4:
            self.caps = struct.unpack('>I', self.value[0:4])[0]


class L2TPBearerCapAVP(L2TPAVP):
    def unpack(self, buf):
        super(L2TPBearerCapAVP, self).unpack(buf)
        if len(self.value) >= 4:
            self.caps = struct.unpack('>I', self.value[0:4])[0]


class L2TPTieBreakerAVP(L2TPAVP):
    def unpack(self, buf):
        super(L2TPTieBreakerAVP, self).unpack(buf)
        if len(self.value) >= 8:
            self.tie = self.value[0:8]


class L2TPFirmwareRevAVP(L2TPAVP):
    def unpack(self, buf):
        super(L2TPFirmwareRevAVP, self).unpack(buf)
        if len(self.value) >= 2:
            self.rev = struct.unpack('>H', self.value[0:2])[0]


class L2TPReceiveWindowAVP(L2TPAVP):
    def unpack(self, buf):
        super(L2TPReceiveWindowAVP, self).unpack(buf)
        if len(self.value) >= 2:
            self.window = struct.unpack('>H', self.value[0:2])[0]


class L2TPChallengeAVP(L2TPAVP):
    def unpack(self, buf):
        super(L2TPChallengeAVP, self).unpack(buf)
        self.challenge = self.value


class L2TPChallengeRespAVP(L2TPAVP):
    def unpack(self, buf):
        super(L2TPChallengeRespAVP, self).unpack(buf)
        self.response = self.value


class L2TPCallingNumberAVP(L2TPAVP):
    def unpack(self, buf):
        super(L2TPCallingNumberAVP, self).unpack(buf)
        self.number = self.value


# AVP dispatch table
_avp_sw = {
    AVP_MSG_TYPE: L2TPMsgTypeAVP,
    AVP_RESULT_CODE: L2TPResultCodeAVP,
    AVP_PROTO_VER: L2TPProtoVerAVP,
    AVP_HOST_NAME: L2TPHostNameAVP,
    AVP_FRAMING_CAP: L2TPFramingCapAVP,
    AVP_BEARER_CAP: L2TPBearerCapAVP,
    AVP_TIE_BREAKER: L2TPTieBreakerAVP,
    AVP_FIRMWARE_REV: L2TPFirmwareRevAVP,
    AVP_VENDOR_NAME: L2TPVendorNameAVP,
    AVP_ASSIGNED_TUNNEL: L2TPAssignedTunnelAVP,
    AVP_RECEIVE_WINDOW: L2TPReceiveWindowAVP,
    AVP_CHALLENGE: L2TPChallengeAVP,
    AVP_CHALLENGE_RESP: L2TPChallengeRespAVP,
    AVP_ASSIGNED_SESSION: L2TPAssignedSessionAVP,
    AVP_CALL_SERIAL: L2TPCallSerialAVP,
    AVP_CALLING_NUMBER: L2TPCallingNumberAVP,
}


def get_avp_parser(vendor, avp_type):
    if vendor != 0:
        return L2TPGenericAVP
    return _avp_sw.get(avp_type, L2TPGenericAVP)


def parse_avps(buf):
    avps = []
    off = 0
    while off + 6 <= len(buf):
        flags = struct.unpack('>H', buf[off:off + 2])[0]
        avp_len = flags & 0x3ff
        if avp_len < 6 or off + avp_len > len(buf):
            break
        vendor = struct.unpack('>H', buf[off + 2:off + 4])[0]
        avp_type = struct.unpack('>H', buf[off + 4:off + 6])[0]
        cls = get_avp_parser(vendor, avp_type)
        avps.append(cls(buf[off:off + avp_len]))
        off += avp_len
    return avps


# ---- L2TP Header + Messages ----
class L2TP(dpkt.Packet):
    __byte_order__ = '>'
    __hdr__ = (
        ('_flags', 'H', 0x0002),       # T(1)+L(1)+rsvd(2)+S(1)+rsvd(1)+ver(4)+rsvd(6)
        ('_length', 'H', 0),
        ('tunnel_id', 'H', 0),
        ('session_id', 'H', 0),
    )
    __bit_fields__ = {
        '_flags': (
            ('t', 1),
            ('l', 1),
            ('_rsv1', 2),
            ('s', 1),
            ('_rsv2', 1),
            ('ver', 4),
            ('_rsv3', 6),
        ),
    }
    _msg_sw = {}

    @property
    def is_control(self):
        return bool(self.t)

    @property
    def is_data(self):
        return not self.t

    @property
    def version(self):
        return self.ver

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        if self.is_control:
            if len(self.data) < 4:
                raise dpkt.NeedData('insufficient control payload')
            extra = struct.unpack('>HH', self.data[0:4])
            ns, nr = extra
            self.ns = ns
            self.nr = nr
            self.avps = parse_avps(self.data[4:])
            msg_type = None
            for avp in self.avps:
                if isinstance(avp, L2TPMsgTypeAVP):
                    msg_type = avp.msg_type
                    break
            cls = self._msg_sw.get(msg_type, L2TPControl)
            self.data = cls()
            self.data.avps = self.avps
            self.data.msg_type = msg_type
        else:
            self.data = self.data  # raw payload


class L2TPControl(dpkt.Packet):
    def __init__(self, *args, **kwargs):
        self.avps = []
        self.msg_type = 0
        super(L2TPControl, self).__init__()


class L2TPSCCRQ(L2TPControl):
    _name = 'sccrq'


class L2TPSCCRP(L2TPControl):
    _name = 'sccrp'


class L2TPSCCCN(L2TPControl):
    _name = 'scccn'


class L2TPStopCCN(L2TPControl):
    _name = 'stopccn'


class L2TPHello(L2TPControl):
    _name = 'hello'


class L2TPOCRQ(L2TPControl):
    _name = 'ocrq'


class L2TPOCRP(L2TPControl):
    _name = 'ocrp'


class L2TPOCCN(L2TPControl):
    _name = 'occn'


class L2TPICRQ(L2TPControl):
    _name = 'icrq'


class L2TPICRP(L2TPControl):
    _name = 'icrp'


class L2TPICCN(L2TPControl):
    _name = 'iccn'


class L2TPCDN(L2TPControl):
    _name = 'cdn'


class L2TPWEN(L2TPControl):
    _name = 'wen'


class L2TPSLI(L2TPControl):
    _name = 'sli'


L2TP._msg_sw.update({
    L2TP_MSG_SCCRQ: L2TPSCCRQ,
    L2TP_MSG_SCCRP: L2TPSCCRP,
    L2TP_MSG_SCCCN: L2TPSCCCN,
    L2TP_MSG_STOPCCN: L2TPStopCCN,
    L2TP_MSG_HELLO: L2TPHello,
    L2TP_MSG_OCRQ: L2TPOCRQ,
    L2TP_MSG_OCRP: L2TPOCRP,
    L2TP_MSG_OCCN: L2TPOCCN,
    L2TP_MSG_ICRQ: L2TPICRQ,
    L2TP_MSG_ICRP: L2TPICRP,
    L2TP_MSG_ICCN: L2TPICCN,
    L2TP_MSG_CDN: L2TPCDN,
    L2TP_MSG_WEN: L2TPWEN,
    L2TP_MSG_SLI: L2TPSLI,
})


# ---- Tests ----
def test_l2tp_header():
    # T=1,L=1,S=1,ver=2,len=20,tid=1,sid=0  + Ns=0,Nr=0 + MsgType AVP (SCCRQ)
    buf = struct.pack('>HHHH', 0xC882, 20, 1, 0) + struct.pack('>HH', 0, 0) + struct.pack('>HHHH', 0x8008, 0, 0, 1)
    pkt = L2TP(buf)
    assert pkt.is_control
    assert pkt.version == 2
    assert pkt.tunnel_id == 1


def test_l2tp_avp():
    # MsgType AVP: M=1,L=8,vendor=0,type=0,value=SCCRQ(1)
    avp_buf = struct.pack('>HHHH', 0x8008, 0, 0, 1)
    avp = L2TPMsgTypeAVP(avp_buf)
    assert avp.m == 1
    assert avp.msg_type == 1


def test_l2tp_sccrq():
    """SCCRQ control message with AVPs."""
    header = struct.pack('>HHHH', 0xc802, 0, 1, 0)  # T=1,L=1,S=1
    ns_nr = struct.pack('>HH', 0, 0)
    avp_msg = struct.pack('>HHHH', 0x8008, 0, AVP_MSG_TYPE, L2TP_MSG_SCCRQ)
    avp_ver = struct.pack('>HHHH', 0x8008, 0, AVP_PROTO_VER, 0x0100)
    avp_host = struct.pack('>HH', 0x800e, 0) + struct.pack('>H', AVP_HOST_NAME) + b'host\x00\x00'
    pkt = L2TP(header + ns_nr + avp_msg + avp_ver + avp_host)
    assert pkt.is_control
    assert isinstance(pkt.data, L2TPSCCRQ)
    assert pkt.data.msg_type == L2TP_MSG_SCCRQ
