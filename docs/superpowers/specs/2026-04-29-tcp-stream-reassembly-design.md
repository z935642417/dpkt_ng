# dpkt TCP Stream Reassembly — Design Specification

**Date:** 2026-04-29  
**Status:** Draft  
**Scope:** dpkt_ng — TCP stream reassembly engine

---

## 1. Overview

Add a TCP stream reassembly engine to dpkt that reconstructs bidirectional byte streams from captured TCP packets. The engine handles packet loss (gaps), retransmissions, and out-of-order delivery using pure TCP sequence-number ordering — no dependency on capture timestamps.

### 1.1 Current State

dpkt parses TCP on a per-packet basis only. There is no flow tracking, sequence-number state, reassembly buffer, or connection management. The `examples/print_http_requests.py` file explicitly documents this gap:

> "Responses almost never will [fit in a single packet]. For proper reconstruction of flows you may want to look at other projects."

### 1.2 Goals

| Goal | Description |
|------|-------------|
| Stream reassembly | Reconstruct contiguous byte streams from TCP segments using sequence numbers |
| Bidirectional | Track both directions independently; optionally merge via seq/ack causality |
| Out-of-order | Buffer out-of-order segments; deliver when gaps fill |
| Retransmission/overlap | Detect and deduplicate overlapping segments |
| Cross-file | Accept packets from multiple pcap files (e.g., one file per direction) |
| Memory safety | Configurable connection count and buffer size limits with eviction |
| Clean API | Pull model (get_data) + optional push callback; dual entry (pcap Reader or IP+TCP) |
| Gap handling | Configurable: skip gaps or fill with 0x00 |

### 1.3 Non-Goals

- Timestamp-based ordering or timeout (user's data often lacks timestamps)
- IP defragmentation (separate concern; engine receives already-defragmented IP packets)
- Built-in protocol parsing (HTTP, SMB) — engine focuses on reassembly only
- TCP option negotiation tracking beyond SYN window scale
- SACK-based selective retransmission handling

---

## 2. File Organization

```
dpkt/
└── stream.py          ✨ New — TCP stream reassembly engine
    ├── DirectionBuffer    # Single-direction reassembly buffer
    ├── Connection         # Bidirectional TCP connection
    └── StreamReassembler  # Engine: connection table + public API
```

Single file, ~500 lines. Follows dpkt convention of one module per feature.

---

## 3. Class Design

### 3.1 DirectionBuffer

Manages reassembly for one direction of a TCP connection.

```
DirectionBuffer:
    # --- State ---
    isn: int | None           # Initial sequence number (from SYN)
    next_seq: int             # Next expected contiguous byte (relative to isn)
    fin_seq: int | None       # Sequence number of FIN (for completion detection)
    syn_received: bool
    fin_received: bool
    
    # --- Buffers ---
    contiguous: bytearray         # Confirmed contiguous data, ready to pull
    segments: list[(seq, ack, data)]  # Out-of-order segments, sorted by seq
                                     # ack stored for merged-mode causal ordering
    
    # --- Stats ---
    total_buffered: int       # Sum of len(contiguous) + sum of segment lengths
    gap_bytes: int            # Total bytes missing (sum of gap sizes)
```

**Core method — `feed(seq: int, ack: int, payload: bytes, flags: int)`：**

```
1. SYN detection:
   If flags & TH_SYN:
       isn = seq
       syn_received = True
       next_seq = 1  (SYN consumes 1 sequence number)
       # Store any payload after SYN
       if len(payload) > 0: process as normal data at seq = seq + 1
       return

2. FIN detection:
   If flags & TH_FIN:
       fin_seq = seq + len(payload)  # FIN is after payload bytes
       fin_received = True

3. If payload is empty: return (pure ACK, nothing to buffer)

4. Compute relative sequence:
   rel_seq = seq - isn
   
5. Overlap/retransmission detection:
   If rel_seq + len(payload) <= next_seq:
       → Fully overlapped / retransmission. Discard.
       return
   If rel_seq < next_seq:
       → Partial overlap. Trim prefix:
       overlap = next_seq - rel_seq
       payload = payload[overlap:]
       rel_seq = next_seq

6. Out-of-order vs contiguous:
   If rel_seq == next_seq:
       → Contiguous! Append to contiguous buffer.
       next_seq += len(payload)
       → Scan segments for cascade merge:
         While segments[0].seq == next_seq:
             Pop segment, append to contiguous, advance next_seq.
    Else: (rel_seq > next_seq)
        → Gap detected. Insert (rel_seq, ack, payload) into segments, sorted by seq.
        → Merge adjacent/overlapping segments in the list.

7. Gap tracking:
   If segments is non-empty:
       gap_bytes = segments[0][0] - next_seq  # bytes missing at head
```

**`get_data(fill_gaps=False) -> bytes`：**

```
If fill_gaps is False:
    Return contiguous, then clear it. (Caller gets only continuous data.)
If fill_gaps is True:
    Build result = contiguous
    For each segment:
        gap_size = segment.seq - current_pos
        If gap_size > 0: result += b'\x00' * gap_size
        result += segment.data
    Clear contiguous and segments.
    Return result.
```

**`flush(fill_gaps=False) -> bytes`：**
Same as `get_data()` but also outputs all buffered segments unconditionally.

**`is_complete` property：**
```
Returns True when:
    syn_received AND fin_received AND next_seq >= fin_seq AND len(segments) == 0
Meaning: all bytes from SYN to FIN have been received contiguously.
```

### 3.2 Connection

Represents one TCP connection (bidirectional).

```
Connection:
    # --- Identity ---
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    
    # --- Direction buffers ---
    c2s: DirectionBuffer    # client → server
    s2c: DirectionBuffer    # server → client
    
    # --- Metadata ---
    client_isn: int | None
    server_isn: int | None
    
    # --- Convenience ---
    @property conn_id: tuple  # (src_ip, src_port, dst_ip, dst_port)
    @property is_closed: bool  # c2s.is_complete and s2c.is_complete
```

**`feed(ip, tcp)`：**
Routes the TCP segment to the correct DirectionBuffer based on port direction:
```
If tcp.sport == self.src_port:
    # Client → Server direction
    self.c2s.feed(tcp.seq, tcp.ack, tcp.data, tcp.flags)
Else:
    # Server → Client direction
    self.s2c.feed(tcp.seq, tcp.ack, tcp.data, tcp.flags)
```

**`get_data(direction='c2s', fill_gaps=False) -> bytes`：**
Delegates to the specified DirectionBuffer.

**`merged_data(fill_gaps=False) -> bytes`：**
For `output_mode='merged'`. Produces a single byte sequence from both directions ordered by seq/ack causality:

```
Algorithm:
1. Collect all segments from c2s and s2c: (dir, seq, ack, data) tuples.
   Include contiguous data as a single segment with seq=next_seq baseline.
2. Sort segments:
   a. Primary key: segments are grouped by their causal relationship.
      If s2c segment has ack that covers c2s segment ending at seq X,
      then c2s segment comes before s2c segment.
   b. Within same direction: sort by seq ascending.
   c. No ack relationship: sort by seq ascending (cross-direction).
3. Concatenate data in sorted order.
4. Apply fill_gaps if requested.
Return the merged byte sequence.
```

### 3.3 StreamReassembler

The engine: manages the connection table and provides the public API.

```
StreamReassembler:
    # --- Configuration ---
    max_connections: int = 10000
    max_buffer_per_dir: int = 16 * 1024 * 1024  # 16 MB
    output_mode: str = 'separate'  # 'separate' | 'merged'
    fill_gaps: bool = False
    
    # --- State ---
    connections: dict[tuple, Connection]  # keyed by 4-tuple (src_ip, src_port, dst_ip, dst_port)
    _callbacks: list[callable]  # Optional push callbacks
    
    # --- Public API ---
    feed(ip, tcp)                    # Feed one parsed packet
    feed_pcap(reader)                # Feed from one pcap Reader
    feed_pcaps(readers: list)        # Feed from multiple pcap Readers
    get_data(conn_id, direction, fill_gaps=...)  # Pull contiguous data
    on_data(callback)                # Register push callback
    flush(conn_id)                   # Force flush all buffered data
    find(src, sport, dst, dport)     # Look up a connection
    __getitem__(conn_id)             # conn = reasm[5-tuple]
```

**`feed(ip, tcp)`：**

```
1. Build connection 5-tuple key: (ip.src, tcp.sport, ip.dst, tcp.dport)
2. If key not in connections:
       If len(connections) >= max_connections: evict_one()
       connections[key] = Connection(...)
   conn = connections[key]
3. conn.feed(ip, tcp)
4. If output_mode == 'merged':
       data = conn.merged_data()
   Else:
       data = conn.c2s.get_data() or conn.s2c.get_data()
5. If data and _callbacks:
       For each callback: callback(conn, data)
6. If conn.is_closed:
       # Connection complete — caller may want to pull final data
```

**`evict_one()`：**
```
Priority order:
1. Find closed connections where all data has been pulled
   (both c2s and s2c: contiguous is empty AND segments is empty).
2. Find closed connections (data not yet fully pulled).
3. Find connection with the largest gap_bytes (least useful).
Remove it from connections dict.
```

**`feed_pcaps(readers)`：**
```
For each reader:
    For timestamp, buf in reader:
        eth = dpkt.ethernet.Ethernet(buf)
        if isinstance(eth.data, dpkt.ip.IP):
            ip = eth.data
            if isinstance(ip.data, dpkt.tcp.TCP):
                self.feed(ip, ip.data)
```
Note: pcap_ng is supported via `dpkt.pcap.UniversalReader`.

---

## 4. Configuration Summary

| Parameter | Default | Description |
|-----------|---------|-------------|
| `max_connections` | 10000 | Maximum tracked connections |
| `max_buffer_per_dir` | 16 MB | Max buffered bytes per direction |
| `output_mode` | `'separate'` | `'separate'` or `'merged'` |
| `fill_gaps` | `False` | Fill gaps with 0x00 in output |

---

## 5. Usage Examples

### 5.1 Separate mode with manual parsing

```python
reasm = dpkt.stream.StreamReassembler(output_mode='separate')

with open('capture.pcap', 'rb') as f:
    for ts, buf in dpkt.pcap.Reader(f):
        eth = dpkt.ethernet.Ethernet(buf)
        if isinstance(eth.data, dpkt.ip.IP):
            ip = eth.data
            if isinstance(ip.data, dpkt.tcp.TCP):
                reasm.feed(ip, ip.data)

# Pull data
for conn_id in reasm.connections:
    conn = reasm[conn_id]
    request = conn.c2s.get_data()
    response = conn.s2c.get_data()
    if request:
        http_req = dpkt.http.Request(request)
    if response:
        http_resp = dpkt.http.Response(response)
```

### 5.2 Multi-file with push callback

```python
def on_smb_data(conn, direction, data):
    smb = dpkt.smb2.SMB2(data)
    if hasattr(smb.data, 'file_data'):
        save_file(smb.data.file_data)

reasm = dpkt.stream.StreamReassembler(max_buffer_per_dir=64*1024*1024)
reasm.on_data(on_smb_data)
reasm.feed_pcaps([
    dpkt.pcap.Reader(open('client.pcap', 'rb')),
    dpkt.pcap.Reader(open('server.pcap', 'rb')),
])
```

### 5.3 Merged mode with gap filling

```python
reasm = dpkt.stream.StreamReassembler(output_mode='merged', fill_gaps=True)
reasm.feed_pcap(reader)
for conn_id in reasm.connections:
    full_stream = reasm[conn_id].merged_data()
    # full_stream is a single byte sequence with both directions causally ordered
```

---

## 6. Testing Strategy

### 6.1 Constructed test flows (primary)

Use dpkt itself to construct TCP packets with known payloads and deliberate anomalies:

```python
def test_out_of_order_reassembly():
    """Packets arrive as seq=200, seq=0, seq=100 → should reassemble to 0..299."""
    buf = DirectionBuffer()
    buf.feed(seq=0, ack=0, payload=b'', flags=dpkt.tcp.TH_SYN)  # SYN
    
    buf.feed(seq=200, ack=0, payload=b'CCC', flags=dpkt.tcp.TH_ACK)
    assert len(buf.get_data()) == 0   # gap at 0-199
    
    buf.feed(seq=0, ack=0, payload=b'AAA', flags=dpkt.tcp.TH_ACK)
    assert buf.get_data() == b'AAA'   # contiguous from 0
    
    buf.feed(seq=100, ack=0, payload=b'BBB', flags=dpkt.tcp.TH_ACK)
    assert buf.get_data() == b'BBBCCC'  # cascade merge fills gaps

def test_overlap_handling():
    """Retransmitted data should be deduplicated."""
    buf = DirectionBuffer()
    buf.feed(seq=0, ack=0, payload=b'', flags=dpkt.tcp.TH_SYN)
    buf.feed(seq=0, ack=0, payload=b'HELLO', flags=dpkt.tcp.TH_ACK)
    buf.feed(seq=0, ack=0, payload=b'HELLO', flags=dpkt.tcp.TH_ACK)  # retransmit
    assert buf.get_data() == b'HELLO'  # no duplication
    assert len(buf.get_data()) == 0    # nothing extra

def test_gap_filling():
    """fill_gaps=True should insert 0x00 in holes."""
    buf = DirectionBuffer()
    buf.feed(seq=0, ack=0, payload=b'', flags=dpkt.tcp.TH_SYN)
    buf.feed(seq=0, ack=0, payload=b'AA', flags=dpkt.tcp.TH_ACK)
    buf.feed(seq=5, ack=0, payload=b'BB', flags=dpkt.tcp.TH_ACK)
    assert buf.get_data(fill_gaps=True) == b'AA\x00\x00\x00BB'

def test_fin_completion():
    """is_complete only when all bytes between SYN and FIN received."""
    buf = DirectionBuffer()
    buf.feed(seq=0, ack=0, payload=b'', flags=dpkt.tcp.TH_SYN)
    buf.feed(seq=0, ack=0, payload=b'DATA', flags=dpkt.tcp.TH_ACK)
    assert not buf.is_complete
    buf.feed(seq=4, ack=0, payload=b'', flags=dpkt.tcp.TH_ACK | dpkt.tcp.TH_FIN)
    assert buf.is_complete  # all bytes between SYN(0) and FIN(4) received

def test_merged_ordering():
    """Server response with ack after client request should be ordered after."""
    conn = Connection()
    conn.c2s.feed(seq=0, ack=0, payload=b'', flags=dpkt.tcp.TH_SYN)
    conn.c2s.feed(seq=0, ack=0, payload=b'GET', flags=dpkt.tcp.TH_ACK)
    conn.s2c.feed(seq=0, ack=0, payload=b'', flags=dpkt.tcp.TH_SYN)
    conn.s2c.feed(seq=0, ack=3, payload=b'HTTP', flags=dpkt.tcp.TH_ACK)
    # Server's ack=3 covers client's seq=0+3, so client data before server data
    merged = conn.merged_data()
    assert b'GET' in merged
    assert merged.index(b'GET') < merged.index(b'HTTP')  # request before response
```

### 6.2 Real pcap samples (secondary)

- Wireshark sample captures (HTTP, SMB)
- Self-captured traffic for regression
- Verify against known expected byte streams

---

## 7. Risks and Mitigations

| Risk | Mitigation |
|------|------------|
| Large segments exhaust memory | `max_buffer_per_dir` enforced; eviction triggered |
| SYN/FIN never seen (truncated pcap) | Caller can call `flush()` to force output of buffered data |
| Sequence number wrap-around (32-bit) | Detect wrap by comparing with isn; handle gracefully |
| Direction assignment ambiguous (both ports same) | Use first-seen SYN to determine client/server roles |
| No timestamps means no idle timeout | Relies on connection/finish detection + manual flush; callers aware |

---

*End of Design Specification*
