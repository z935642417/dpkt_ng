# EIGRP Protocol Support — Design Specification

**Date:** 2026-04-29  
**Status:** Draft  
**Scope:** dpkt_ng — EIGRP (IPv4 + IPv6) protocol parsing

---

## 1. Overview

Add a new `dpkt/eigrp.py` module providing complete EIGRP (Enhanced Interior Gateway Routing Protocol) parsing for both IPv4 and IPv6. Uses IP protocol 88 for both.

### 1.1 Current State

`IP_PROTO_EIGRP = 88` exists in `dpkt/ip.py` (line 286). No EIGRP module exists. No EIGRP code anywhere in the codebase.

### 1.2 Goals

| Goal | Description |
|------|-------------|
| EIGRP header | 20-byte header (version, opcode, checksum, flags, seq, ack, ASN) |
| Message types | Hello(5), Update(1), Query(3), Reply(4), SIA-Query(10), SIA-Reply(11) |
| TLV parsing | Parameter(0x0001), Internal Route(0x0102), External Route(0x0103) |
| Wide Metrics | Sub-TLV parsing for scaled metrics (0x0601, 0x0602) |
| IPv4 + IPv6 | Unified EIGRP class; AFI-based distinction in route TLVs |
| Extensible TLV | Generic base class for unknown TLV types |
| Checksum | Auto-calculation in __bytes__ |
| Integration | IP._protosw[88] auto-dispatches |

### 1.3 Non-Goals

- Authentication verification (fields stored, not validated)
- EIGRP over IPv6 extension headers (handled by IP6._protosw[88])
- Stub router extensions
- OTP (Over The Top) EIGRP

---

## 2. File Organization

```
dpkt/eigrp.py  (~400 lines, new file)
├── Constants: opcodes, TLV types, AFI values, flags
├── EIGRP header class with opcode dispatch
├── 6 message subclasses (Hello/Update/Query/Reply/SIA-Query/SIA-Reply)
├── EIGRPTLV base class + EIGRPGenericTLV fallback
├── EIGRPParamTLV (0x0001)
├── EIGRPInternalRouteTLV (0x0102) + Wide Metrics sub-TLVs
├── EIGRPExternalRouteTLV (0x0103) + Wide Metrics sub-TLVs
└── ~10 inline pytest tests
```

---

## 3. EIGRP Header (20 bytes)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Version     |    Opcode     |           Checksum            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                             Flags                             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           Sequence                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Acknowledgment                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                   Autonomous System Number                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

```python
class EIGRP(dpkt.Packet):
    __byte_order__ = '>'
    __hdr__ = (
        ('v', 'B', 2),       # version (1 or 2)
        ('opcode', 'B', 0),  # message type
        ('sum', 'H', 0),     # checksum (standard IP checksum)
        ('flags', 'I', 0),   # flags
        ('seq', 'I', 0),     # sequence number
        ('ack', 'I', 0),     # acknowledgment number
        ('asn', 'I', 0),     # autonomous system number
    )

    def __bytes__(self):
        if not self.sum:
            self.sum = dpkt.in_cksum(dpkt.Packet.__bytes__(self))
        return dpkt.Packet.__bytes__(self)
```

### 3.1 Constants

```python
# Opcodes
EIGRP_OP_UPDATE = 1
EIGRP_OP_QUERY = 3
EIGRP_OP_REPLY = 4
EIGRP_OP_HELLO = 5
EIGRP_OP_SIAQUERY = 10
EIGRP_OP_SIAREPLY = 11

# Flags
EIGRP_FLAG_INIT = 0x01
EIGRP_FLAG_CONDITIONAL_RECEIVE = 0x02
EIGRP_FLAG_RESTART = 0x04
EIGRP_FLAG_ENDOFTABLE = 0x08

# TLV types
EIGRP_TLV_PARAM = 0x0001
EIGRP_TLV_AUTH = 0x0002
EIGRP_TLV_INTERNAL_ROUTE = 0x0102
EIGRP_TLV_EXTERNAL_ROUTE = 0x0103

# Wide Metrics sub-TLV types
EIGRP_METRIC_SCALED = 0x0601
EIGRP_METRIC_EXTENDED = 0x0602

# Address Family Identifiers
AFI_IPV4 = 1
AFI_IPV6 = 16384
```

---

## 4. TLV Framework

### 4.1 Base Classes

```python
class EIGRPTLV(object):
    """Base TLV: type(2B) + length(2B) + value(variable)."""
    def __init__(self, buf=None):
        self.type = 0
        self.length = 4
        self.value = b''
        if buf:
            self.unpack(buf)

    def unpack(self, buf):
        self.type, self.length = struct.unpack('>HH', buf[:4])
        self.value = buf[4:self.length]

    def __bytes__(self):
        return struct.pack('>HH', self.type, self.length) + self.value

    def __len__(self):
        return self.length


class EIGRPGenericTLV(EIGRPTLV):
    """Fallback TLV for unknown types. Stores raw value bytes."""
    pass
```

### 4.2 Parameter TLV (0x0001)

```
Type=0x0001, Length=12
Value: k1(1B)|k2(1B)|k3(1B)|k4(1B)|k5(1B)|rsvd(3B)|hold_time(2B)
```

```python
class EIGRPParamTLV(EIGRPTLV):
    def __init__(self, k1=0, k2=0, k3=1, k4=0, k5=0, hold_time=15):
        self.k1 = k1; self.k2 = k2; self.k3 = k3
        self.k4 = k4; self.k5 = k5
        self.hold_time = hold_time

    def unpack(self, buf):
        super().unpack(buf)
        if len(self.value) >= 10:
            self.k1, self.k2, self.k3, self.k4, self.k5 = \
                struct.unpack('BBBBB', self.value[:5])
            self.hold_time = struct.unpack('>H', self.value[8:10])[0]

    def __bytes__(self):
        value = struct.pack('BBBBB3sH',
            self.k1, self.k2, self.k3, self.k4, self.k5,
            b'\x00' * 3, self.hold_time)
        self.length = 4 + len(value)
        return struct.pack('>HH', 0x0001, self.length) + value
```

### 4.3 Internal Route TLV (0x0102)

```
Type=0x0102, Value:
  next_hop(4B) + delay(4B) + bandwidth(4B) + mtu(3B) + hop_count(1B)
  + reliability(1B) + load(1B) + rsvd(2B) + prefix_len(1B) + prefix(variable)
  [optional: Wide Metric sub-TLVs starting after prefix...]
```

```python
class EIGRPInternalRouteTLV(EIGRPTLV):
    _metric_sw = {}  # sub-TLV type → class

    def __init__(self, *args, **kwargs):
        self.metrics = []  # Wide Metric sub-TLVs
        super().__init__(*args, **kwargs) if args else None
        if not args and not kwargs.get('buf'):
            self.next_hop = 0; self.delay = 0; self.bandwidth = 0
            self.mtu = 1500; self.hop_count = 0; self.reliability = 255
            self.load = 1; self.prefix_length = 0; self.prefix = b''

    def unpack(self, buf):
        EIGRPTLV.unpack(self, buf)
        if len(self.value) < 26:
            return
        self.next_hop = struct.unpack('>I', self.value[0:4])[0]
        self.delay = struct.unpack('>I', self.value[4:8])[0]
        self.bandwidth = struct.unpack('>I', self.value[8:12])[0]
        self.mtu = struct.unpack('>I', self.value[12:15] + b'\x00')[0] >> 8
        self.hop_count = self.value[15]
        self.reliability = self.value[16]
        self.load = self.value[17]
        self.prefix_length = self.value[20]

        prefix_bytes = (self.prefix_length + 7) // 8
        self.prefix = self.value[21:21 + prefix_bytes]
        pos = 21 + prefix_bytes

        # Parse optional Wide Metric sub-TLVs
        self.metrics = []
        while pos + 4 <= len(self.value):
            stype, slen = struct.unpack('>HH', self.value[pos:pos + 4])
            cls = self._metric_sw.get(stype, EIGRPGenericMetricTLV)
            try:
                sub = cls(self.value[pos:pos + slen])
                self.metrics.append(sub)
            except (struct.error, ValueError):
                break
            pos += slen

    def __bytes__(self):
        prefix_bytes = (self.prefix_length + 7) // 8
        value = struct.pack('>III', self.next_hop, self.delay, self.bandwidth)
        value += struct.pack('>I', self.mtu << 8)[:3]
        value += bytes([self.hop_count, self.reliability, self.load, 0, 0,
                        self.prefix_length])
        value += self.prefix + b'\x00' * (prefix_bytes - len(self.prefix))
        for m in self.metrics:
            value += bytes(m)
        self.length = 4 + len(value)
        return struct.pack('>HH', self.type or 0x0102, self.length) + value
```

### 4.4 External Route TLV (0x0103)

Same as Internal Route TLV but with additional fields after prefix:
```
origin_router(4B) + origin_as(4B) + tag(4B) + ext_proto(1B) + flags(1B) + rsvd(2B)
```

`EIGRPExternalRouteTLV` extends `EIGRPInternalRouteTLV` and adds parsing of these extra fields.

### 4.5 Wide Metric Sub-TLVs

```python
class EIGRPScaledMetricTLV(EIGRPTLV):
    """0x0601: Scaled delay + bandwidth (8 bytes)."""
    def unpack(self, buf):
        super().unpack(buf)
        if len(self.value) >= 8:
            self.scaled_delay = struct.unpack('>I', self.value[0:4])[0]
            self.scaled_bandwidth = struct.unpack('>I', self.value[4:8])[0]

class EIGRPExtendedMetricTLV(EIGRPTLV):
    """0x0602: Jitter + energy + flags (12 bytes)."""
    def unpack(self, buf):
        super().unpack(buf)
        if len(self.value) >= 12:
            self.jitter = struct.unpack('>I', self.value[0:4])[0]
            self.energy = struct.unpack('>I', self.value[4:8])[0]
            self.rflags = self.value[8]
```

### 4.6 TLV Dispatch Registration

```python
EIGRP._tlv_sw = {
    EIGRP_TLV_PARAM: EIGRPParamTLV,
    EIGRP_TLV_INTERNAL_ROUTE: EIGRPInternalRouteTLV,
    EIGRP_TLV_EXTERNAL_ROUTE: EIGRPExternalRouteTLV,
}

EIGRPInternalRouteTLV._metric_sw = {
    EIGRP_METRIC_SCALED: EIGRPScaledMetricTLV,
    EIGRP_METRIC_EXTENDED: EIGRPExtendedMetricTLV,
}
```

---

## 5. Message Types

### 5.1 Message Subclasses

All message types share the same EIGRP header and differ only in the TLVs they carry. Each subclass overrides `unpack()` to parse the TLVs:

```python
class EIGRPHello(EIGRP):
    _msg_name = 'Hello'
    def unpack(self, buf):
        self.tlvs = []
        off = 0
        while off + 4 <= len(buf):
            tlv_type = struct.unpack('>H', buf[off:off+2])[0]
            cls = EIGRP._tlv_sw.get(tlv_type, EIGRPGenericTLV)
            tlv = cls(buf[off:])
            self.tlvs.append(tlv)
            off += tlv.length
        self.data = b''
```

Other message classes (Update, Query, Reply, SIA-Query, SIA-Reply) follow the identical pattern.

### 5.2 Opcode Dispatch

```python
class EIGRP(dpkt.Packet):
    _opcode_sw = {
        EIGRP_OP_UPDATE: EIGRPUpdate,
        EIGRP_OP_QUERY: EIGRPQuery,
        EIGRP_OP_REPLY: EIGRPReply,
        EIGRP_OP_HELLO: EIGRPHello,
        EIGRP_OP_SIAQUERY: EIGRPSIAQuery,
        EIGRP_OP_SIAREPLY: EIGRPSIAReply,
    }

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        cls = self._opcode_sw.get(self.opcode)
        if cls:
            self.data = cls(self.data)
            setattr(self, self.data._msg_name.lower(), self.data)
```

---

## 6. Integration with dpkt

### 6.1 IP Dispatch

`IP_PROTO_EIGRP = 88` already defined. `__load_protos()` auto-discovers `dpkt.eigrp.EIGRP` and registers at `IP._protosw[88]`. IPv6 shares `_protosw` dict.

### 6.2 dpkt/__init__.py

Add `from . import eigrp` in alphabetical position (after `edp` or before `ethernet`).

---

## 7. Testing Strategy

| # | Test | Coverage |
|---|------|----------|
| 1 | Header parse | version=2, opcode=5, asn field |
| 2 | Hello + Parameter TLV | K-values, hold_time |
| 3 | Update + Internal Route | IPv4 prefix, metrics |
| 4 | Update + External Route | IPv4 prefix, origin_router, tag |
| 5 | Wide Metrics | Scaled delay/bandwidth sub-TLV |
| 6 | IPv6 Route | AFI=16384, IPv6 prefix |
| 7 | Multiple TLVs | Param + Route in same packet |
| 8 | Unknown TLV | Generic fallback |
| 9 | Checksum | Auto-calc |
| 10 | Roundtrip | Construct → bytes → parse |

---

## 8. Risks and Mitigations

| Risk | Mitigation |
|------|------------|
| IPv6 prefix length > 128 | Validate; truncate or raise |
| TLV length mismatch | Use min(len(buf), self.length) for safety |
| Wide Metrics vs legacy only | Detect remaining bytes after prefix; try sub-TLV parse |
| Multiple route TLVs in one Update | Loop over TLVs in unpack() |

---

*End of Design Specification*
