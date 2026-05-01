# -*- coding: utf-8 -*-
"""IEEE 802.11 Information Elements."""
from __future__ import absolute_import, print_function
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
