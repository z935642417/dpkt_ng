# OSPF Protocol Support — Design Specification

**Date:** 2026-04-29  
**Status:** Draft  
**Scope:** dpkt_ng — OSPFv2 (RFC 2328) + OSPFv3 (RFC 5340) full protocol parsing

---

## 1. Overview

Complete rewrite of `dpkt/ospf.py` to support full OSPFv2 and OSPFv3 parsing including all 5 message types, complete LSA body parsing with type dispatch, auto version detection, and round-trip serialization.

### 1.1 Current State

`dpkt/ospf.py` (64 lines): Only parses the 24-byte common header (v/type/len/router/area/sum/atype/auth). No message type dispatch, no LSA parsing, no version detection.

### 1.2 Goals

| Goal | Description |
|------|-------------|
| OSPFv2 | Full 5 message types + 5 LSA types with body parsing |
| OSPFv3 | Full 5 message types + 8 LSA types with body parsing |
| Auto version | Factory `__new__` inspecting `v` field |
| LSA dispatch | Dict-based `_lsa_sw` mapping type codes to classes |
| Checksum | Auto-calculation in `__bytes__` (existing behavior) |
| Integration | IP._protosw[89] auto-dispatches; no IP/IP6 changes |

### 1.3 Non-Goals

- Auth verification (fields stored but not validated)
- LLS (Link-Local Signaling) and Crypto Sequence Number
- OSPFv3 over IPv4
- Graceful Restart extensions
- Opaque LSA types (9/10/11)

---

## 2. File Organization

```
dpkt/ospf.py  (~800 lines, complete rewrite)
├── Constants: version, msg types, LSA types, auth types
├── OSPF base class + factory __new__
├── OSPFv2 + 5 message classes
├── OSPFv3 + 5 message classes
├── LSAv2Header + 5 LSA subclasses
├── LSAv3Header + 8 LSA subclasses
└── ~15 inline pytest tests
```

---

## 3. Class Hierarchy

### 3.1 OSPF Base Class

```python
class OSPF(dpkt.Packet):
    __hdr__ = (
        ('v', 'B', 0),        # version (2 or 3)
        ('type', 'B', 0),     # message type
        ('len', 'H', 0),      # packet length
        ('router', 'I', 0),   # router ID
        ('area', 'I', 0),     # area ID
        ('sum', 'H', 0),      # checksum (standard IP checksum)
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
```

### 3.2 OSPFv2 Subclass

```python
class OSPFv2(OSPF):
    __hdr__ = OSPF.__hdr__ + (
        ('atype', 'H', 0),     # auth type
        ('auth', '8s', b''),   # auth data
    )
    _msg_sw = {}  # populated by _mod_init()
    
    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        cls = self._msg_sw.get(self.type)
        if cls:
            self.data = cls(buf[self.__hdr_len__:])
        # else: keep raw data
```

### 3.3 OSPFv3 Subclass

```python
class OSPFv3(OSPF):
    __hdr__ = OSPF.__hdr__ + (
        ('instance_id', 'B', 0),
        ('rsvd', 'B', 0),
    )
    _msg_sw = {}  # populated by _mod_init()
    
    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        cls = self._msg_sw.get(self.type)
        if cls:
            self.data = cls(buf[self.__hdr_len__:])
```

---

## 4. Message Types

### 4.1 Constants

```python
OSPF_MSG_HELLO = 1
OSPF_MSG_DBD = 2
OSPF_MSG_LSR = 3
OSPF_MSG_LSU = 4
OSPF_MSG_LSACK = 5
OSPF_VERSION_2 = 2
OSPF_VERSION_3 = 3
```

### 4.2 OSPFv2 Message Subclasses

**OSPFv2Hello** — fields: `network_mask(I), hello_interval(H), options(B), router_priority(B), dead_interval(I), designated_router(I), backup_designated_router(I), neighbors[I...]`

**OSPFv2DBD** — fields: `mtu(H), options(B), flags(B), seq(I), lsa_headers[LSAv2Header...]`

**OSPFv2LSR** — fields: `requests[(type:I, id:I, adv_router:I)...]`

**OSPFv2LSU** — fields: `lsa_count(I), lsas[LSAv2...]` with `_lsa_sw` dispatch

**OSPFv2LSAck** — fields: `lsa_headers[LSAv2Header...]`

### 4.3 OSPFv3 Message Subclasses

**OSPFv3Hello** — fields: `interface_id(I), router_priority(B), options(3s), hello_interval(H), dead_interval(H), designated_router(I), backup_designated_router(I), neighbors[I...]`

**OSPFv3DBD** — fields: `options(3s), flags(B), seq(I), lsa_headers[LSAv3Header...]`

**OSPFv3LSR** — fields: `requests[(type:H, id:I, adv_router:I)...]` (note: type is 2 bytes in v3)

**OSPFv3LSU** — fields: `lsa_count(I), lsas[LSAv3...]` with `_lsa_sw` dispatch

**OSPFv3LSAck** — fields: `lsa_headers[LSAv3Header...]`

---

## 5. LSA Class Hierarchy

### 5.1 LSAv2Header (20 bytes)

```python
class LSAv2Header(dpkt.Packet):
    __hdr__ = (
        ('age', 'H', 0),
        ('opts', 'B', 0),
        ('type', 'B', 0),        # 1=Router, 2=Network, 3=Summary-IP, 4=Summary-ASBR, 5=AS-External
        ('id', 'I', 0),
        ('adv_router', 'I', 0),
        ('seq', 'I', 0),
        ('sum', 'H', 0),
        ('len', 'H', 20),
    )
```

### 5.2 OSPFv2 LSA Types

**LSARouter (type=1)** — body: `flags(B)+rsv(B)+link_count(H), links[(id:I, data:I, type:B, tos:B, metric:H)...]`

**LSANetwork (type=2)** — body: `mask(I), routers[I...]`

**LSASummaryIP (type=3)** — body: `mask(I), metric(3s packed)`

**LSASummaryASBR (type=4)** — body: `mask(I), metric(3s packed)`

**LSAASExternal (type=5)** — body: `mask(I), flags(B)+metric(3s)+forwarding(I)+tag(I)`

### 5.3 LSAv3Header (24 bytes)

```python
class LSAv3Header(dpkt.Packet):
    __hdr__ = (
        ('age', 'H', 0),
        ('_type_field', 'H', 0),  # U16 LS type (bit_fields)
        ('id', 'I', 0),
        ('adv_router', 'I', 0),
        ('seq', 'I', 0),
        ('sum', 'H', 0),
        ('len', 'H', 24),
    )
```

### 5.4 OSPFv3 LSA Types

**LSARouterV3 (type=0x2001)** — body: `flags(B)+opts(3s), links[(type:B+rsv:B+metric:H+if_id:I+neighbor_if_id:I+neighbor_router:I)...]`

**LSANetworkV3 (type=0x2002)** — body: `opts(3s), routers[I...]`

**LSAInterAreaPrefix (type=0x2003)** — body: `metric(3s)+prefix_len(B)+prefix()`

**LSAInterAreaRouter (type=0x2004)** — body: `opts(3s)+rsv(B)+metric(3s)+dest_router(I)`

**LSAASExternalV3 (type=0x4005)** — body: `flags(B)+metric(3s), prefix_len(B)+prefix()+forwarding(I)+tag(I)`

**LSANSSAV3 (type=0x2007)** — body: same as AS-External structure

**LSALink (type=0x0008)** — body: `pri(B)+opts(3s), prefix_len(B)+prefix()`

**LSAIntraAreaPrefix (type=0x2009)** — body: `lsa_count(H)+ref_type(H)+ref_id(I)+ref_adv_router(I), prefixes[(prefix_len:B+prefix:variable)...]`

### 5.5 LSA Type Dispatch

Each LSU message class maintains its own `_lsa_sw` dict:

```python
# OSPFv2LSU
_lsa_sw = {
    1: LSARouter,
    2: LSANetwork,
    3: LSASummaryIP,
    4: LSASummaryASBR,
    5: LSAASExternal,
}

# OSPFv3LSU
_lsa_sw = {
    0x2001: LSARouterV3,
    0x2002: LSANetworkV3,
    0x2003: LSAInterAreaPrefix,
    0x2004: LSAInterAreaRouter,
    0x4005: LSAASExternalV3,
    0x2007: LSANSSAV3,
    0x0008: LSALink,
    0x2009: LSAIntraAreaPrefix,
}
```

---

## 6. Checksum

OSPF packet checksum uses standard IP checksum (RFC 1071) over the entire packet excluding the auth field for v2. The existing auto-calculation logic in `OSPF.__bytes__()` is preserved:

```python
def __bytes__(self):
    if not self.sum:
        self.sum = dpkt.in_cksum(dpkt.Packet.__bytes__(self))
    return dpkt.Packet.__bytes__(self)
```

LSA individual checksums (`LSAv2Header.sum`, `LSAv3Header.sum`) are stored as parsed fields but not auto-calculated (Fletcher checksum differs from IP checksum).

---

## 7. Integration with dpkt

### 7.1 IP/IPv6 Dispatch (no changes needed)

`IP_PROTO_OSPF = 89` already defined in `dpkt/ip.py`. `__load_protos()` auto-discovers `dpkt.ospf.OSPF`. `IP6._protosw` shares `IP._protosw` dict, so OSPFv3 is automatically dispatched for IPv6 next-header 89.

### 7.2 dpkt/__init__.py

`from . import ospf` already exists at line 48. No change needed.

### 7.3 Module Auto-Loading

```python
# In ospf.py
def _mod_init():
    """Populate message type dispatch tables."""
    for cls, sw in [(OSPFv2, OSPFv2._msg_sw), (OSPFv3, OSPFv3._msg_sw)]:
        for name, val in globals().items():
            if name.startswith('OSPF_MSG_'):
                cls_name = 'OSPFv2' + name[9:].title() if cls is OSPFv2 else 'OSPFv3' + name[9:].title()
                cmd_cls = globals().get(cls_name)
                if cmd_cls and isinstance(cmd_cls, type):
                    sw[val] = cmd_cls
```

---

## 8. Testing Strategy

### 8.1 Tests (~15 tests)

| # | Test | Coverage |
|---|------|----------|
| 1 | `test_ospf_v2_auto_detect` | Factory returns OSPFv2 for v=2 |
| 2 | `test_ospf_v3_auto_detect` | Factory returns OSPFv3 for v=3 |
| 3 | `test_ospf_v2_hello` | Hello with mask, interval, neighbors |
| 4 | `test_ospf_v2_dbd` | DBD with LSA headers |
| 5 | `test_ospf_v2_lsu_router_lsa` | LSU containing Router-LSA with links |
| 6 | `test_ospf_v2_lsu_as_external` | LSU containing AS-External LSA |
| 7 | `test_ospf_v2_auth` | Password/MD5 auth fields |
| 8 | `test_ospf_v3_hello` | Hello with interface_id, 3B options |
| 9 | `test_ospf_v3_lsu_router_lsa_v3` | v3 Router-LSA with v3 link format |
| 10 | `test_ospf_v3_intra_area_prefix` | Intra-Area-Prefix with prefixes |
| 11 | `test_ospf_v3_as_external` | v3 AS-External with prefix+tag |
| 12 | `test_ospf_checksum` | Auto-calc when sum==0 |
| 13 | `test_ospf_roundtrip_v2` | Construct v2 → bytes → parse |
| 14 | `test_ospf_roundtrip_v3` | Construct v3 → bytes → parse |
| 15 | `test_ospf_unknown_type` | Unknown msg type → raw data |

### 8.2 Real pcap (secondary)

- OSPFv2 adjacency formation captures
- OSPFv3 IPv6 network captures

---

## 9. Risks and Mitigations

| Risk | Mitigation |
|------|------------|
| Large LSA sets (1000+ LSAs in one LSU) | Use offset-based iteration; don't pre-allocate lists |
| LSA length field mismatch | Validate length; skip malformed LSA with UnpackError fallback |
| Sequence number wrap | Store as unsigned int; comparison handled by user |
| v2 vs v3 field naming clashes | Use version-specific class prefixes |
| Backward compat with existing ospf.py | Complete rewrite but preserves __hdr__ pattern and checksum logic |

---

*End of Design Specification*
