# -*- coding: utf-8 -*-
"""IEEE 802.11 Information Elements."""
from __future__ import absolute_import, print_function
import struct
from . import dpkt


class IEEE80211IE(dpkt.Packet):
    """IE base: id(1B) + len(1B) + info(variable)."""
    __byte_order__ = '<'
    __hdr__ = (
        ('id', 'B', 0),
        ('len', 'B', 0),
    )

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        self.info = buf[2:2 + self.len]
        self.data = b''

    @classmethod
    def parse(cls, buf):
        if len(buf) < 2:
            return None, 0
        ie = cls(buf)
        return ie, 2 + ie.len


# IE type registries
_ie_registry = {}       # {ie_id: IE_class}
_ext_ie_registry = {}   # {ext_id: IE_class} for tag 255


def register_ie(ie_id, ie_cls, ext_id=None):
    """Register an IE parser class."""
    if ext_id is not None:
        _ext_ie_registry[ext_id] = ie_cls
    else:
        _ie_registry[ie_id] = ie_cls


def get_ie_parser(ie_id, ext_id=None):
    """Look up IE parser by (id, optional ext_id)."""
    if ie_id == 255 and ext_id is not None:
        return _ext_ie_registry.get(ext_id, IEEE80211IE)
    return _ie_registry.get(ie_id, IEEE80211IE)


def unpack_ies(buf):
    """Parse all IEs from buffer, handling extension tags."""
    ies = []
    off = 0
    while off + 2 <= len(buf):
        ie_id = buf[off]
        ie_len = buf[off + 1]
        if off + 2 + ie_len > len(buf):
            break
        if ie_id == 255 and ie_len >= 1:
            ext_id = buf[off + 2]
            cls = get_ie_parser(ie_id, ext_id)
        else:
            cls = get_ie_parser(ie_id)
        ies.append(cls(buf[off:off + 2 + ie_len]))
        off += 2 + ie_len
    return ies


# IE IDs
IE_HT_CAPA = 45
IE_HT_INFO = 61
IE_VHT_CAPA = 191
IE_VHT_OP = 192
IE_ERP = 42
IE_RSN = 48
IE_EXT_CAP = 127
IE_COUNTRY = 7


class IEEE80211IEHTCapability(IEEE80211IE):
    """HT Capabilities IE (45)."""
    def unpack(self, buf):
        super().unpack(buf)
        if len(self.info) >= 26:
            self.ht_cap_info = struct.unpack('<H', self.info[0:2])[0]
            self.ampdu_params = self.info[2]
            self.mcs_set = self.info[3:19]
            self.ht_ext_cap = struct.unpack('<H', self.info[19:21])[0]
            self.beamforming = struct.unpack('<I', self.info[21:25])[0]
            self.asel = self.info[25]


class IEEE80211IEHTInfo(IEEE80211IE):
    """HT Information IE (61)."""
    def unpack(self, buf):
        super().unpack(buf)
        if len(self.info) >= 22:
            self.primary_ch = self.info[0]
            self.ht_info_config = struct.unpack('<H', self.info[1:3])[0]
            self.basic_mcs = self.info[6:22]


class IEEE80211IEVHTCapability(IEEE80211IE):
    """VHT Capabilities IE (191)."""
    def unpack(self, buf):
        super().unpack(buf)
        if len(self.info) >= 12:
            self.vht_cap_info = struct.unpack('<I', self.info[0:4])[0]
            rx_map, tx_map = struct.unpack('<HH', self.info[4:8])
            self.mcs_map = (rx_map, tx_map)
            self.rx_mcs = rx_map
            self.tx_mcs = tx_map


class IEEE80211IEVHTOperation(IEEE80211IE):
    """VHT Operation IE (192)."""
    def unpack(self, buf):
        super().unpack(buf)
        if len(self.info) >= 5:
            self.ch_width = self.info[0]
            self.ch1 = self.info[1]
            self.ch2 = struct.unpack('<H', self.info[2:4])[0]
            self.basic_mcs = struct.unpack('<H', self.info[4:6])[0]


class IEEE80211IEERP(IEEE80211IE):
    """ERP IE (42) — 1 byte flags."""
    def unpack(self, buf):
        super().unpack(buf)
        if self.info:
            self.flags = self.info[0]


class IEEE80211IERSN(IEEE80211IE):
    """RSN IE (48) — WPA2/WPA3."""
    def unpack(self, buf):
        super().unpack(buf)
        if len(self.info) >= 8:
            self.version = struct.unpack('<H', self.info[0:2])[0]
            self.group_suite = self.info[2:6]
            self.pairwise_count = struct.unpack('<H', self.info[6:8])[0]
            off = 8
            self.pairwise = []
            for _ in range(self.pairwise_count):
                if off + 4 <= len(self.info):
                    self.pairwise.append(self.info[off:off+4])
                    off += 4
            self.akm_count = 0
            self.akm = []
            if off + 2 <= len(self.info):
                self.akm_count = struct.unpack('<H', self.info[off:off+2])[0]
                off += 2
            for _ in range(self.akm_count):
                if off + 4 <= len(self.info):
                    self.akm.append(self.info[off:off+4])
                    off += 4
            self.caps = 0
            if off + 2 <= len(self.info):
                self.caps = struct.unpack('<H', self.info[off:off+2])[0]


class IEEE80211IEExtCap(IEEE80211IE):
    """Extended Capabilities IE (127)."""
    def unpack(self, buf):
        super().unpack(buf)
        self.flags = self.info


class IEEE80211IECountry(IEEE80211IE):
    """Country IE (7)."""
    def unpack(self, buf):
        super().unpack(buf)
        self.country_code = self.info[:3] if len(self.info) >= 3 else b''
        self.triplets = []
        off = 3
        while off + 3 <= len(self.info):
            pwr = self.info[off+2]
            if isinstance(pwr, int) and pwr > 127:
                pwr = pwr - 256  # signed byte
            self.triplets.append({
                'channel': self.info[off],
                'channels': self.info[off+1],
                'power': pwr,
            })
            off += 3


# Register HT/VHT IEs
for ie_id, cls in [
    (IE_HT_CAPA, IEEE80211IEHTCapability),
    (IE_HT_INFO, IEEE80211IEHTInfo),
    (IE_VHT_CAPA, IEEE80211IEVHTCapability),
    (IE_VHT_OP, IEEE80211IEVHTOperation),
    (IE_ERP, IEEE80211IEERP),
    (IE_RSN, IEEE80211IERSN),
    (IE_EXT_CAP, IEEE80211IEExtCap),
    (IE_COUNTRY, IEEE80211IECountry),
]:
    register_ie(ie_id, cls)


def test_ie_parse():
    """Basic IE parsing."""
    buf = bytes([0, 4, 0x41, 0x42, 0x43, 0x44])
    ie = IEEE80211IE(buf)
    assert ie.id == 0
    assert ie.len == 4
    assert ie.info == b'ABCD'


def test_ie_registry():
    """Type registry returns correct class or fallback."""
    register_ie(99, IEEE80211IE)
    assert get_ie_parser(99) is IEEE80211IE
    assert get_ie_parser(999) is IEEE80211IE  # fallback


def test_ie_unpack_ies():
    """Bulk IE parser with multiple IEs."""
    buf = bytes([0, 4, 0x41, 0x41, 0x41, 0x41, 1, 2, 0x42, 0x42])
    ies = unpack_ies(buf)
    assert len(ies) == 2
    assert ies[0].id == 0
    assert ies[1].id == 1


def test_ht_capa_ie():
    """HT Capabilities IE roundtrip."""
    buf = bytes([45, 26]) + b'\x6c\x00' + bytes([0]) + b'\x00'*16 + b'\x00\x00' + b'\x00'*4 + bytes([0])
    ie = IEEE80211IEHTCapability(buf)
    assert ie.id == IE_HT_CAPA
    assert ie.ht_cap_info == 0x006c  # LE: 0x6c00 → 0x006c


def test_vht_capa_ie():
    """VHT Capabilities IE roundtrip."""
    buf = bytes([191, 12]) + b'\x00'*4 + b'\xaa\xaa\x00\x00' + b'\x00'*4
    ie = IEEE80211IEVHTCapability(buf)
    assert ie.id == IE_VHT_CAPA
    assert ie.rx_mcs == 0xaaaa


def test_rsn_ie():
    """RSN IE with group suite + pairwise + AKM."""
    # version(2) + group(4) + pairwise_count(2) + pairwise(4) + akm_count(2) + akm(4) + caps(2) = 20
    info = struct.pack('<H', 1) + b'\x00\x0f\xac\x04' + struct.pack('<H', 1) + b'\x00\x0f\xac\x04' + struct.pack('<H', 1) + b'\x00\x0f\xac\x02' + struct.pack('<H', 0)
    buf = bytes([IE_RSN, len(info)]) + info
    ie = IEEE80211IERSN(buf)
    assert ie.id == IE_RSN
    assert ie.version == 1
    assert len(ie.pairwise) == 1
    assert len(ie.akm) == 1
    assert ie.caps == 0


def test_country_ie():
    """Country IE with triplets."""
    # country(3) + triplet0(3) + triplet1(3) = 9
    info = b'US ' + bytes([1, 11, 30]) + bytes([36, 4, 20])
    buf = bytes([IE_COUNTRY, len(info)]) + info
    ie = IEEE80211IECountry(buf)
    assert ie.country_code == b'US '
    assert len(ie.triplets) == 2
    assert ie.triplets[0]['channel'] == 1
