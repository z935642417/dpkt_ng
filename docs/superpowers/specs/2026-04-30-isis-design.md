# IS-IS Protocol Support — Design Specification

**Date:** 2026-04-30  
**Status:** Draft  
**Scope:** dpkt_ng — IS-IS (ISO 10589) protocol parsing

---

## 1. Overview

Add `dpkt/isis.py` providing complete IS-IS protocol parsing with all 9 PDU types and 7 core TLVs. Extend `dpkt/llc.py` for OSI encapsulation (dsap=0xfe). Add `ETH_TYPE_ISIS` to `dpkt/ethernet.py`.

### 1.1 Non-Goals

- IS-IS for IPv6 (uses different NLPID and TLV codes)
- TE (Traffic Engineering) extensions
- Sub-TLV parsing within Extended IS Reachability (store raw)
- Checksum verification (store only)

---

## 2. File Organization

```
dpkt/isis.py       ✨ ~450行 — 新增
dpkt/llc.py        📝 +3行 — dsap=0xfe → ISIS 分派
dpkt/ethernet.py   📝 +1行 — ETH_TYPE_ISIS = 0x22F0
dpkt/__init__.py   📝 +1行 — from . import isis
```

---

## 3. IS-IS Header (8 bytes)

| Offset | Field | Format | Default |
|--------|-------|--------|---------|
| 0 | nlpid | B | 0x83 |
| 1 | hdr_len | B | 0 |
| 2 | version | B | 1 |
| 3 | id_len | B | 0 (→ 6) |
| 4 | _pdu_type | B | 0 |
| 5 | version2 | B | 1 |
| 6 | rsvd | B | 0 |
| 7 | max_area | B | 0 |

`id_len=0` means default 6 bytes. `_pdu_type` 1-9 dispatches to PDU subclasses.

---

## 4. PDU Types (9 total)

| Code | Class | Specific Fields |
|------|-------|----------------|
| 1 | ISISLANHelloL1 | circuit_type, source_id(6B), hold_time, pdu_len, priority, lan_id(7B) |
| 2 | ISISLANHelloL2 | same as L1 |
| 3 | ISISP2PHello | circuit_type, source_id, hold_time, pdu_len, local_circuit_id |
| 4 | ISISLSPL1 | pdu_len, remaining_life, lsp_id(8B), seq, checksum |
| 5 | ISISLSPL2 | same |
| 6 | ISISCSNPL1 | pdu_len, source_id(8B), start_lsp_id(8B), end_lsp_id(8B) |
| 7 | ISISCSNPL2 | same |
| 8 | ISISPSNPL1 | pdu_len, source_id(8B) |
| 9 | ISISPSNPL2 | same |

---

## 5. TLV Framework

### 5.1 Base Class

```python
class ISISTLV(object):
    def unpack(self, buf):
        self.type = buf[0]; self.length = buf[1]; self.value = buf[2:2+self.length]
    def __bytes__(self): return bytes([self.type, len(self.value)]) + self.value
    def __len__(self): return 2 + len(self.value)
```

### 5.2 Core TLVs

| Type | Class | Body |
|------|-------|------|
| 1 | ISISAreaAddrTLV | value = raw area address bytes |
| 6 | ISISNeighborsTLV | value parsed as list of 6-byte system IDs |
| 10 | ISISAuthTLV | value = raw auth data |
| 22 | ISISEISReachTLV | groups of 11+N bytes (neighbor_id+metric+subTLVs) |
| 128 | ISISIPIntReachTLV | groups of 12 bytes (metric+ctrl+prefix+mask) |
| 129 | ISISProtoSupTLV | value = NLPID bytes |
| 130 | ISISIPExtReachTLV | same format as 128 |

### 5.3 Dispatch

```python
ISIS._tlv_sw = {1: AreaAddr, 6: Neighbors, 10: Auth, 22: EISReach,
                 128: IPInt, 129: ProtoSup, 130: IPExt}
```

---

## 6. LLC Integration

```python
# dpkt/llc.py unpack() — add after existing elif chain:
elif self.dsap == 0xfe:
    from .isis import ISIS
    self.data = self.isis = ISIS(self.data)
```

```python
# dpkt/ethernet.py
ETH_TYPE_ISIS = 0x22F0
```

---

## 7. Testing (~8 inline tests)

| Test | Coverage |
|------|----------|
| Header + NLPID | 0x83, id_len, PDU type |
| LAN Hello | circuit_type, source_id, DIS |
| P2P Hello | local_circuit_id |
| LSP | remaining_life, lsp_id, seq |
| CSNP | LSP range entries |
| AreaAddrTLV | area list |
| NeighborsTLV | neighbor system IDs |
| Roundtrip | construct → bytes → parse |

---

*End of Design Specification*
