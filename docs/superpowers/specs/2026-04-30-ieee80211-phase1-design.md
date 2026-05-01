# IEEE 802.11 Modernization — Phase 1 Design

**Date:** 2026-04-30 | **Scope:** Byte order + Frame Control + IE framework | **Backward Compatible:** Yes

---

## 1. Overview

Phase 1 addresses three foundational issues:
1. **Byte order**: Fix big-endian default to little-endian
2. **Frame Control**: Replace ~200 lines of manual property with `__bit_fields__`
3. **IE Framework**: Extract to `dpkt/ieee80211_ie.py` with type-registry + extension tag (255) support

All changes strictly backward compatible.

---

## 2. Byte Order Fix

Set `__byte_order__ = '<'` on IEEE80211 base class. Remove all `ntole()` / `ntole64()` patches. All `__hdr__` fields automatically read/written in correct byte order via metaclass.

---

## 3. Frame Control __bit_fields__

Replace 10 manual `@property` definitions with:
```python
__bit_fields__ = {
    '_framectl': (
        ('version', 2), ('type', 2), ('subtype', 4),
        ('to_ds', 1), ('from_ds', 1), ('more_frag', 1), ('retry', 1),
        ('pwr_mgt', 1), ('more_data', 1), ('wep', 1), ('order', 1),
    ),
}
```
Property names preserved.

---

## 4. IE Framework (`dpkt/ieee80211_ie.py`)

### Base class: `IEEE80211IE(dpkt.Packet)`
- __hdr__: `id(B) + len(B)`, info stored as `self.info`, `self.data = b''`

### Type registry:
- `_ie_registry = {id: class}` for standard IE IDs
- `_ext_ie_registry = {ext_id: class}` for IE ID 255 extension tags
- `register_ie(id, cls, ext_id=None)` and `get_ie_parser(id, ext_id=None)` functions

### IE parser: `unpack_ies(buf)` — parses all IEs with extension tag auto-detection

---

## 5. Integration

- `ieee80211.py`: byte order + __bit_fields__ + import IEs from ieee80211_ie
- `ieee80211_ie.py`: new file, IE framework
- All 16 existing tests pass unchanged
