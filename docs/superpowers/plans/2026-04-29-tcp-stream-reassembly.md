# TCP Stream Reassembly Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a TCP stream reassembly engine (`dpkt/stream.py`) that reconstructs bidirectional byte streams from captured TCP packets using pure sequence-number ordering.

**Architecture:** Three classes in one module — `DirectionBuffer` (single-direction seq tracking, gap buffering, overlap dedup), `Connection` (bidirectional pair of buffers + merged seq/ack ordering), `StreamReassembler` (connection table, eviction, dual API: pcap Reader or IP+TCP feed). Follows dpkt conventions: inline pytest tests, `from . import dpkt` style, `__future__` imports.

**Tech Stack:** Python 3, `struct`, `bytearray`, pytest (inline `def test_*` in module file)

---

## File Map

| File | Action | Responsibility |
|------|--------|---------------|
| `dpkt/stream.py` | **Create** | DirectionBuffer → Connection → StreamReassembler + ~12 inline tests |
| `dpkt/__init__.py` | **Modify** | Add `from . import stream` import |

---

### Task 1: DirectionBuffer — Core Reassembly (SYN + contiguous + out-of-order)

**Files:**
- Create: `dpkt/stream.py`

- [ ] **Step 1: Write failing tests**

```python
# dpkt/stream.py
# -*- coding: utf-8 -*-
"""TCP stream reassembly."""
from __future__ import print_function
from __future__ import absolute_import

import struct

from . import dpkt
from . import tcp as tcp_mod


class DirectionBuffer(object):
    """Reassembly buffer for one direction of a TCP connection."""
    def __init__(self):
        self.isn = None
        self.next_seq = 0
        self.fin_seq = None
        self.syn_received = False
        self.fin_received = False
        self.contiguous = bytearray()
        self.segments = []  # [(rel_seq, ack, data), ...] sorted by rel_seq
        self.total_buffered = 0

    def feed(self, seq, ack, payload, flags):
        pass

    def get_data(self, fill_gaps=False):
        return b''

    @property
    def is_complete(self):
        return False


def test_direction_buffer_syn():
    """SYN sets ISN and advances next_seq by 1."""
    buf = DirectionBuffer()
    buf.feed(seq=1000, ack=0, payload=b'', flags=tcp_mod.TH_SYN)
    assert buf.syn_received
    assert buf.isn == 1000
    assert buf.next_seq == 1  # relative: seq 1 after SYN

def test_direction_buffer_contiguous():
    """Contiguous data is immediately available."""
    buf = DirectionBuffer()
    buf.feed(seq=0, ack=0, payload=b'', flags=tcp_mod.TH_SYN)
    buf.feed(seq=0, ack=0, payload=b'HELLO', flags=tcp_mod.TH_ACK)
    assert buf.get_data() == b'HELLO'
    assert buf.next_seq == 5

def test_direction_buffer_out_of_order():
    """Out-of-order segments are buffered and delivered when gaps fill."""
    buf = DirectionBuffer()
    buf.feed(seq=0, ack=0, payload=b'', flags=tcp_mod.TH_SYN)
    # Segment at seq=3 arrives first (gap at 0-2)
    buf.feed(seq=3, ack=0, payload=b'LO', flags=tcp_mod.TH_ACK)
    assert buf.get_data() == b''  # gap exists
    assert len(buf.segments) == 1
    # Segment at seq=0 fills the gap
    buf.feed(seq=0, ack=0, payload=b'HEL', flags=tcp_mod.TH_ACK)
    assert buf.get_data() == b'HELLO'
    assert len(buf.segments) == 0
```

- [ ] **Step 2: Run to verify failure**

Run: `python -m pytest dpkt/stream.py -v -p no:cacheprovider -o "addopts="`
Expected: 3 FAIL (stub implementations)

- [ ] **Step 3: Implement core feed() and get_data()**

```python
class DirectionBuffer(object):
    def __init__(self):
        self.isn = None
        self.next_seq = 0          # relative to isn
        self.fin_seq = None
        self.syn_received = False
        self.fin_received = False
        self.contiguous = bytearray()
        self.segments = []         # [(rel_seq, ack, data), ...] sorted by rel_seq
        self.total_buffered = 0

    def feed(self, seq, ack, payload, flags):
        # SYN detection
        if flags & tcp_mod.TH_SYN:
            self.isn = seq
            self.syn_received = True
            self.next_seq = 1
            if payload:
                # Payload after SYN (unusual but possible)
                self.contiguous.extend(payload)
                self.next_seq += len(payload)
                self.total_buffered += len(payload)
            return

        if self.isn is None:
            return  # can't process without ISN

        # FIN detection
        if flags & tcp_mod.TH_FIN:
            self.fin_seq = seq + len(payload)
            self.fin_received = True

        if not payload:
            return

        rel_seq = seq - self.isn

        # Overlap/retransmission: fully overlapped
        if rel_seq + len(payload) <= self.next_seq:
            return

        # Partial overlap: trim prefix
        if rel_seq < self.next_seq:
            overlap = self.next_seq - rel_seq
            payload = payload[overlap:]
            rel_seq = self.next_seq

        # Contiguous
        if rel_seq == self.next_seq:
            self.contiguous.extend(payload)
            self.next_seq += len(payload)
            self.total_buffered += len(payload)
            # Cascade merge: check if next segment(s) now connect
            while self.segments and self.segments[0][0] <= self.next_seq:
                seg_rel_seq, seg_ack, seg_data = self.segments.pop(0)
                if seg_rel_seq + len(seg_data) > self.next_seq:
                    new_start = self.next_seq - seg_rel_seq
                    self.contiguous.extend(seg_data[new_start:])
                    self.next_seq += len(seg_data) - new_start
        else:
            # Out-of-order: insert sorted by rel_seq
            self.segments.append((rel_seq, ack, payload))
            self.segments.sort(key=lambda x: x[0])
            self.total_buffered += len(payload)
            # Merge overlapping adjacent segments
            merged = []
            for seg in self.segments:
                if merged and merged[-1][0] + len(merged[-1][2]) >= seg[0]:
                    prev_seq, prev_ack, prev_data = merged[-1]
                    overlap_off = seg[0] - prev_seq
                    if overlap_off < len(prev_data):
                        new_data = prev_data[:overlap_off] + seg[2]
                    else:
                        gap = overlap_off - len(prev_data)
                        new_data = prev_data + b'\x00' * gap + seg[2]
                    merged[-1] = (prev_seq, prev_ack, new_data)
                else:
                    merged.append(seg)
            self.segments = merged

    def get_data(self, fill_gaps=False):
        if fill_gaps:
            result = bytes(self.contiguous)
            pos = self.next_seq
            for rel_seq, ack, data in self.segments:
                gap = rel_seq - pos
                if gap > 0:
                    result += b'\x00' * gap
                    pos = rel_seq
                result += data
                pos += len(data)
            self.contiguous = bytearray()
            self.segments = []
            self.total_buffered = 0
            return result
        else:
            data = bytes(self.contiguous)
            self.contiguous = bytearray()
            self.total_buffered -= len(data)
            return data

    @property
    def is_complete(self):
        if self.fin_seq is None:
            return False
        return (self.syn_received and self.fin_received
                and self.next_seq >= (self.fin_seq - self.isn)
                and len(self.segments) == 0)
```

- [ ] **Step 4: Run tests to verify pass**

Run: `python -m pytest dpkt/stream.py -v -p no:cacheprovider -o "addopts="`
Expected: 3 PASS

- [ ] **Step 5: Commit**

```bash
git add dpkt/stream.py
git commit -m "feat: add DirectionBuffer with SYN, contiguous, and out-of-order reassembly"
```

---

### Task 2: DirectionBuffer — Edge Cases (overlap, retransmit, FIN, completion, flush)

**Files:**
- Modify: `dpkt/stream.py`

- [ ] **Step 1: Write failing tests for edge cases**

```python
def test_direction_buffer_overlap():
    """Retransmitted/overlapping data is deduplicated."""
    buf = DirectionBuffer()
    buf.feed(seq=0, ack=0, payload=b'', flags=tcp_mod.TH_SYN)
    buf.feed(seq=0, ack=0, payload=b'HELLO', flags=tcp_mod.TH_ACK)
    buf.feed(seq=0, ack=0, payload=b'HELLO', flags=tcp_mod.TH_ACK)  # full retransmit
    assert buf.get_data() == b'HELLO'
    assert buf.get_data() == b''  # nothing extra

def test_direction_buffer_partial_overlap():
    """Partially overlapping segment: new bytes after overlap are kept."""
    buf = DirectionBuffer()
    buf.feed(seq=0, ack=0, payload=b'', flags=tcp_mod.TH_SYN)
    buf.feed(seq=0, ack=0, payload=b'HELLO', flags=tcp_mod.TH_ACK)
    buf.get_data()
    # Retransmit with extra data appended
    buf.feed(seq=2, ack=0, payload=b'LLOWORLD', flags=tcp_mod.TH_ACK)
    assert buf.get_data() == b'WORLD'

def test_direction_buffer_fin_complete():
    """is_complete only when all bytes between SYN and FIN received."""
    buf = DirectionBuffer()
    buf.feed(seq=0, ack=0, payload=b'', flags=tcp_mod.TH_SYN)
    assert not buf.is_complete
    buf.feed(seq=0, ack=0, payload=b'DATA', flags=tcp_mod.TH_ACK)
    assert not buf.is_complete  # FIN not yet seen
    buf.feed(seq=4, ack=0, payload=b'', flags=tcp_mod.TH_ACK | tcp_mod.TH_FIN)
    assert buf.is_complete  # all bytes between SYN(0) and FIN(4) contiguous

def test_direction_buffer_fin_with_gap():
    """FIN seen but gap remains → not complete."""
    buf = DirectionBuffer()
    buf.feed(seq=0, ack=0, payload=b'', flags=tcp_mod.TH_SYN)
    buf.feed(seq=5, ack=0, payload=b'DATA', flags=tcp_mod.TH_ACK)
    assert not buf.is_complete
    buf.feed(seq=9, ack=0, payload=b'', flags=tcp_mod.TH_ACK | tcp_mod.TH_FIN)
    assert not buf.is_complete  # gap 0-4
    buf.feed(seq=0, ack=0, payload=b'HELLO', flags=tcp_mod.TH_ACK)
    assert buf.is_complete  # now all bytes received

def test_direction_buffer_flush():
    """flush() outputs all data even with gaps."""
    buf = DirectionBuffer()
    buf.feed(seq=0, ack=0, payload=b'', flags=tcp_mod.TH_SYN)
    buf.feed(seq=0, ack=0, payload=b'AA', flags=tcp_mod.TH_ACK)
    buf.feed(seq=5, ack=0, payload=b'BB', flags=tcp_mod.TH_ACK)
    result = buf.get_data(fill_gaps=True)
    assert result == b'AA\x00\x00\x00BB'
    assert buf.total_buffered == 0

def test_direction_buffer_flush_no_fill():
    """flush(fill_gaps=False) only outputs contiguous data."""
    buf = DirectionBuffer()
    buf.feed(seq=0, ack=0, payload=b'', flags=tcp_mod.TH_SYN)
    buf.feed(seq=0, ack=0, payload=b'AA', flags=tcp_mod.TH_ACK)
    buf.feed(seq=5, ack=0, payload=b'BB', flags=tcp_mod.TH_ACK)
    assert buf.get_data() == b'AA'
    assert buf.get_data() == b''
    assert len(buf.segments) == 1  # BB still buffered
```

- [ ] **Step 2: Run to verify failure**

Run: `python -m pytest dpkt/stream.py::test_direction_buffer_overlap dpkt/stream.py::test_direction_buffer_fin_complete -v -p no:cacheprovider -o "addopts="`
Expected: some FAIL (gap/fin tests may pass, overlap may need refinement)

- [ ] **Step 3: Verify all edge case tests pass**

Run: `python -m pytest dpkt/stream.py -v -p no:cacheprovider -o "addopts="`
Expected: 9 PASS (3 from Task 1 + 6 new)

- [ ] **Step 4: Commit**

```bash
git add dpkt/stream.py
git commit -m "feat: add DirectionBuffer overlap, FIN completion, flush with gap filling"
```

---

### Task 3: Connection — Bidirectional Routing + merged_data()

**Files:**
- Modify: `dpkt/stream.py`

- [ ] **Step 1: Write failing tests for Connection**

```python
def test_connection_routing():
    """Connection routes packets to correct direction based on sport."""
    conn = Connection(src_ip='10.0.0.1', src_port=12345, dst_ip='10.0.0.2', dst_port=445)
    # SYN from client
    conn.c2s.feed(seq=100, ack=0, payload=b'', flags=tcp_mod.TH_SYN)
    conn.c2s.feed(seq=100, ack=0, payload=b'CMD', flags=tcp_mod.TH_ACK)
    # SYN from server
    conn.s2c.feed(seq=5000, ack=0, payload=b'', flags=tcp_mod.TH_SYN)
    conn.s2c.feed(seq=5000, ack=0, payload=b'RSP', flags=tcp_mod.TH_ACK)
    assert conn.c2s.get_data() == b'CMD'
    assert conn.s2c.get_data() == b'RSP'

def test_connection_merged_ordering():
    """merged_data() orders by seq/ack causality."""
    conn = Connection(src_ip='10.0.0.1', src_port=12345, dst_ip='10.0.0.2', dst_port=445)
    # Client sends request
    conn.c2s.feed(seq=0, ack=0, payload=b'', flags=tcp_mod.TH_SYN)
    conn.c2s.feed(seq=0, ack=0, payload=b'GET', flags=tcp_mod.TH_ACK)
    # Server sends response, ack=3 covers client's seq=0+3
    conn.s2c.feed(seq=0, ack=0, payload=b'', flags=tcp_mod.TH_SYN)
    conn.s2c.feed(seq=0, ack=3, payload=b'HTTP', flags=tcp_mod.TH_ACK)
    merged = conn.merged_data()
    assert merged == b'GETHTTP'

def test_connection_properties():
    """conn_id and is_closed properties."""
    conn = Connection(src_ip='10.0.0.1', src_port=12345, dst_ip='10.0.0.2', dst_port=80)
    assert conn.conn_id == ('10.0.0.1', 12345, '10.0.0.2', 80)
    assert not conn.is_closed
```

- [ ] **Step 2: Run to verify failure**

Run: `python -m pytest dpkt/stream.py::test_connection_routing -v -p no:cacheprovider -o "addopts="`
Expected: FAIL (Connection not defined)

- [ ] **Step 3: Implement Connection class**

```python
class Connection(object):
    """One TCP connection with bidirectional reassembly buffers."""
    def __init__(self, src_ip, src_port, dst_ip, dst_port):
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.c2s = DirectionBuffer()
        self.s2c = DirectionBuffer()
        self.client_isn = None
        self.server_isn = None

    @property
    def conn_id(self):
        return (self.src_ip, self.src_port, self.dst_ip, self.dst_port)

    @property
    def is_closed(self):
        return self.c2s.is_complete and self.s2c.is_complete

    def feed(self, ip, tcp):
        """Feed a parsed IP+TCP packet to the correct direction."""
        if tcp.sport == self.src_port:
            self.c2s.feed(tcp.seq, tcp.ack, tcp.data, tcp.flags)
        else:
            self.s2c.feed(tcp.seq, tcp.ack, tcp.data, tcp.flags)

    def merged_data(self, fill_gaps=False):
        """Return a single byte sequence with both directions ordered by seq/ack causality."""
        # Collect segments from both directions, including contiguous data
        items = []  # [(dir, rel_seq, ack, data), ...]
        # c2s contiguous
        if self.c2s.contiguous:
            items.append(('c2s', self.c2s.next_seq - len(self.c2s.contiguous),
                         0, bytes(self.c2s.contiguous)))
        for rel_seq, ack, data in self.c2s.segments:
            items.append(('c2s', rel_seq, ack, data))
        # s2c contiguous
        if self.s2c.contiguous:
            base = self.s2c.next_seq - len(self.s2c.contiguous)
            items.append(('s2c', base, 0, bytes(self.s2c.contiguous)))
        for rel_seq, ack, data in self.s2c.segments:
            items.append(('s2c', rel_seq, ack, data))

        if not items:
            return b''

        # Sort by causality: if s2c.ack covers c2c seq range, c2c comes first
        def sort_key(item):
            direction, rel_seq, ack, data = item
            # Primary: lower seq first (within same direction)
            # Secondary: c2s before s2c when no ack relationship
            return (rel_seq, 0 if direction == 'c2s' else 1)

        items.sort(key=sort_key)

        # Build merged output
        result = bytearray()
        pos = 0
        for direction, rel_seq, ack, data in items:
            if fill_gaps and rel_seq > pos:
                result.extend(b'\x00' * (rel_seq - pos))
            if not fill_gaps:
                result.extend(data)
            else:
                overlap = max(0, pos - rel_seq)
                if overlap < len(data):
                    result.extend(data[overlap:])
            pos = max(pos, rel_seq + len(data))

        # Clear both buffers after merge
        self.c2s.contiguous = bytearray()
        self.c2s.segments = []
        self.c2s.total_buffered = 0
        self.s2c.contiguous = bytearray()
        self.s2c.segments = []
        self.s2c.total_buffered = 0

        return bytes(result)
```

- [ ] **Step 4: Run tests to verify pass**

Run: `python -m pytest dpkt/stream.py -v -p no:cacheprovider -o "addopts="`
Expected: 12 PASS (9 from Tasks 1-2 + 3 new)

- [ ] **Step 5: Commit**

```bash
git add dpkt/stream.py
git commit -m "feat: add Connection bidirectional routing and merged seq/ack ordering"
```

---

### Task 4: StreamReassembler — Connection Table + feed + Eviction

**Files:**
- Modify: `dpkt/stream.py`

- [ ] **Step 1: Write failing tests**

```python
def test_stream_reassembler_feed():
    """Feed IP+TCP creates connections and reassembles data."""
    reasm = StreamReassembler(max_connections=100, max_buffer_per_dir=1024*1024)
    # Build minimal IP+TCP objects using dpkt
    ip = dpkt.ip.IP(src=b'\x0a\x00\x00\x01', dst=b'\x0a\x00\x00\x02', p=6)
    tcp_pkt = dpkt.tcp.TCP(sport=12345, dport=445, seq=100, flags=tcp_mod.TH_SYN, data=b'')
    ip.data = tcp_pkt
    reasm.feed(ip, tcp_pkt)
    conn_id = ('10.0.0.1', 12345, '10.0.0.2', 445)
    assert conn_id in reasm.connections
    conn = reasm[conn_id]
    assert conn.c2s.syn_received

def test_stream_reassembler_eviction():
    """Eviction when max_connections exceeded."""
    reasm = StreamReassembler(max_connections=3, max_buffer_per_dir=1024)
    for i in range(5):
        ip = dpkt.ip.IP(src=b'\x0a\x00\x00\x01', dst=b'\x0a\x00\x00\x02', p=6)
        tcp_pkt = dpkt.tcp.TCP(sport=10000+i, dport=445, seq=100, flags=tcp_mod.TH_SYN, data=b'')
        ip.data = tcp_pkt
        reasm.feed(ip, tcp_pkt)
    assert len(reasm.connections) == 3  # evicted 2

def test_stream_reassembler_find():
    """find() looks up connection by address/port."""
    reasm = StreamReassembler()
    ip = dpkt.ip.IP(src=b'\x0a\x00\x00\x01', dst=b'\x0a\x00\x00\x02', p=6)
    tcp_pkt = dpkt.tcp.TCP(sport=12345, dport=445, seq=100, flags=tcp_mod.TH_SYN, data=b'')
    ip.data = tcp_pkt
    reasm.feed(ip, tcp_pkt)
    conn = reasm.find(src='10.0.0.1', sport=12345, dst='10.0.0.2', dport=445)
    assert conn is not None
    assert reasm.find(src='10.0.0.1', sport=99999, dst='10.0.0.2', dport=445) is None
```

- [ ] **Step 2: Run to verify failure**

Run: `python -m pytest dpkt/stream.py::test_stream_reassembler_feed -v -p no:cacheprovider -o "addopts="`
Expected: FAIL

- [ ] **Step 3: Implement StreamReassembler class**

```python
class StreamReassembler(object):
    """TCP stream reassembly engine."""
    def __init__(self, max_connections=10000, max_buffer_per_dir=16*1024*1024,
                 output_mode='separate', fill_gaps=False):
        self.max_connections = max_connections
        self.max_buffer_per_dir = max_buffer_per_dir
        self.output_mode = output_mode
        self.fill_gaps = fill_gaps
        self.connections = {}  # keyed by 4-tuple
        self._callbacks = []

    def feed(self, ip, tcp_pkt):
        """Feed one parsed IP+TCP packet."""
        conn_id = (dpkt.compat.inet_to_str(ip.src), tcp_pkt.sport,
                   dpkt.compat.inet_to_str(ip.dst), tcp_pkt.dport)
        if conn_id not in self.connections:
            if len(self.connections) >= self.max_connections:
                self._evict_one()
            self.connections[conn_id] = Connection(
                src_ip=conn_id[0], src_port=conn_id[1],
                dst_ip=conn_id[2], dst_port=conn_id[3])
        conn = self.connections[conn_id]
        conn.feed(ip, tcp_pkt)
        # Check buffer limits
        for buf in (conn.c2s, conn.s2c):
            if buf.total_buffered > self.max_buffer_per_dir:
                # Force flush to avoid OOM
                buf.get_data(fill_gaps=self.fill_gaps)
        return conn

    def _evict_one(self):
        """Remove one connection to make room."""
        # Priority 1: closed + fully pulled
        for cid, conn in list(self.connections.items()):
            if conn.is_closed and not conn.c2s.contiguous and not conn.c2s.segments \
               and not conn.s2c.contiguous and not conn.s2c.segments:
                del self.connections[cid]
                return
        # Priority 2: closed
        for cid, conn in list(self.connections.items()):
            if conn.is_closed:
                del self.connections[cid]
                return
        # Priority 3: most gap_bytes
        if self.connections:
            worst = max(self.connections.items(),
                       key=lambda x: x[1].c2s.total_buffered - len(x[1].c2s.contiguous)
                                     + x[1].s2c.total_buffered - len(x[1].s2c.contiguous))
            del self.connections[worst[0]]

    def find(self, src=None, sport=None, dst=None, dport=None):
        for cid, conn in self.connections.items():
            if (src is None or cid[0] == src) and \
               (sport is None or cid[1] == sport) and \
               (dst is None or cid[2] == dst) and \
               (dport is None or cid[3] == dport):
                return conn
        return None

    def __getitem__(self, conn_id):
        return self.connections[conn_id]

    def __contains__(self, conn_id):
        return conn_id in self.connections

    def __iter__(self):
        return iter(self.connections)

    def __len__(self):
        return len(self.connections)
```

- [ ] **Step 4: Run tests to verify pass**

Run: `python -m pytest dpkt/stream.py -v -p no:cacheprovider -o "addopts="`
Expected: 15 PASS (12 existing + 3 new)

- [ ] **Step 5: Commit**

```bash
git add dpkt/stream.py
git commit -m "feat: add StreamReassembler with connection table, feed, eviction, find"
```

---

### Task 5: StreamReassembler — pcap Entry Points

**Files:**
- Modify: `dpkt/stream.py`

- [ ] **Step 1: Write failing test with real pcap construction**

```python
def test_stream_reassembler_feed_pcap():
    """feed_pcap() iterates pcap Reader and calls feed()."""
    import io
    from . import pcap as pcap_mod
    from . import ethernet as eth_mod
    # Build a minimal pcap in memory with one SYN packet
    # Construct Ethernet / IP / TCP / payload
    tcp_pkt = dpkt.tcp.TCP(sport=12345, dport=80, seq=0, flags=tcp_mod.TH_SYN, data=b'')
    ip_pkt = dpkt.ip.IP(src=b'\x0a\x00\x00\x01', dst=b'\x0a\x00\x00\x02', p=6, data=tcp_pkt)
    eth_pkt = eth_mod.Ethernet(src=b'\x00'*6, dst=b'\x00'*6, type=eth_mod.ETH_TYPE_IP, data=ip_pkt)
    pkt_bytes = bytes(eth_pkt)
    # Write minimal pcap file
    pcap_hdr = struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)  # Ethernet DLT=1
    pkt_hdr = struct.pack('<IIII', 0, 0, len(pkt_bytes), len(pkt_bytes))
    f = io.BytesIO(pcap_hdr + pkt_hdr + pkt_bytes)

    reasm = StreamReassembler()
    reasm.feed_pcap(pcap_mod.Reader(f))
    assert len(reasm.connections) >= 1
```

- [ ] **Step 2: Run to verify failure**

Run: `python -m pytest dpkt/stream.py::test_stream_reassembler_feed_pcap -v -p no:cacheprovider -o "addopts="`
Expected: FAIL (feed_pcap not defined)

- [ ] **Step 3: Implement feed_pcap and feed_pcaps**

```python
    def feed_pcap(self, reader):
        """Feed all packets from one pcap Reader."""
        for timestamp, buf in reader:
            self._process_packet(buf)

    def feed_pcaps(self, readers):
        """Feed packets from multiple pcap Readers."""
        for reader in readers:
            self.feed_pcap(reader)

    def _process_packet(self, buf):
        """Parse Ethernet→IP→TCP and feed to engine."""
        try:
            eth = dpkt.ethernet.Ethernet(buf)
        except (dpkt.UnpackError, dpkt.NeedData):
            return
        if not isinstance(eth.data, dpkt.ip.IP):
            return
        ip = eth.data
        if not isinstance(ip.data, dpkt.tcp.TCP):
            return
        self.feed(ip, ip.data)
```
Note: `import struct` is already at the top of the file (added in Task 1).

- [ ] **Step 4: Run tests to verify pass**

Run: `python -m pytest dpkt/stream.py -v -p no:cacheprovider -o "addopts="`
Expected: 16 PASS

- [ ] **Step 5: Commit**

```bash
git add dpkt/stream.py
git commit -m "feat: add pcap entry points (feed_pcap, feed_pcaps)"
```

---

### Task 6: StreamReassembler — Callbacks + Flush

**Files:**
- Modify: `dpkt/stream.py`

- [ ] **Step 1: Write callback test**

```python
def test_stream_reassembler_callback():
    """on_data() callback fires when new contiguous data arrives."""
    collected = []
    def cb(conn, data):
        collected.append(data)

    ip = dpkt.ip.IP(src=b'\x0a\x00\x00\x01', dst=b'\x0a\x00\x00\x02', p=6)
    tcp_pkt = dpkt.tcp.TCP(sport=12345, dport=80, seq=0, flags=tcp_mod.TH_SYN, data=b'')
    ip.data = tcp_pkt

    reasm = StreamReassembler()
    reasm.on_data(cb)
    reasm.feed(ip, tcp_pkt)
    # SYN has no payload, no callback yet

    ip2 = dpkt.ip.IP(src=b'\x0a\x00\x00\x01', dst=b'\x0a\x00\x00\x02', p=6)
    tcp_pkt2 = dpkt.tcp.TCP(sport=12345, dport=80, seq=0, flags=tcp_mod.TH_ACK, data=b'HELLO')
    ip2.data = tcp_pkt2
    reasm.feed(ip2, tcp_pkt2)
    assert len(collected) == 1
    assert collected[0] == b'HELLO'

def test_stream_reassembler_flush():
    """flush() forces all buffered data out."""
    ip = dpkt.ip.IP(src=b'\x0a\x00\x00\x01', dst=b'\x0a\x00\x00\x02', p=6)
    tcp_pkt = dpkt.tcp.TCP(sport=12345, dport=80, seq=0, flags=tcp_mod.TH_SYN, data=b'')
    ip.data = tcp_pkt
    reasm = StreamReassembler()
    reasm.feed(ip, tcp_pkt)
    # Feed out-of-order data without filling gap
    ip2 = dpkt.ip.IP(src=b'\x0a\x00\x00\x01', dst=b'\x0a\x00\x00\x02', p=6)
    tcp_pkt2 = dpkt.tcp.TCP(sport=12345, dport=80, seq=3, flags=tcp_mod.TH_ACK, data=b'LO')
    ip2.data = tcp_pkt2
    reasm.feed(ip2, tcp_pkt2)
    conn = reasm.find(src='10.0.0.1', sport=12345, dst='10.0.0.2', dport=80)
    data = conn.c2s.get_data(fill_gaps=True)
    assert data == b'\x00\x00\x00LO'
```

- [ ] **Step 2: Run to verify failure → implement → run to verify pass**

Add to StreamReassembler class:

```python
    def on_data(self, callback):
        """Register a callback called when new contiguous data arrives.
        Signature: callback(connection, data_bytes)."""
        self._callbacks.append(callback)

    def feed(self, ip, tcp_pkt):
        """Feed one parsed IP+TCP packet."""
        conn_id = (dpkt.compat.inet_to_str(ip.src), tcp_pkt.sport,
                   dpkt.compat.inet_to_str(ip.dst), tcp_pkt.dport)
        if conn_id not in self.connections:
            if len(self.connections) >= self.max_connections:
                self._evict_one()
            self.connections[conn_id] = Connection(
                src_ip=conn_id[0], src_port=conn_id[1],
                dst_ip=conn_id[2], dst_port=conn_id[3])
        conn = self.connections[conn_id]
        conn.feed(ip, tcp_pkt)
        # Check for new contiguous data in separate mode
        if self.output_mode == 'separate':
            data_c2s = conn.c2s.get_data(fill_gaps=self.fill_gaps)
            data_s2c = conn.s2c.get_data(fill_gaps=self.fill_gaps)
            for cb in self._callbacks:
                if data_c2s:
                    cb(conn, data_c2s)
                if data_s2c:
                    cb(conn, data_s2c)
        else:  # merged mode
            data = conn.merged_data(fill_gaps=self.fill_gaps)
            for cb in self._callbacks:
                if data:
                    cb(conn, data)
        # Check buffer limits
        for buf in (conn.c2s, conn.s2c):
            if buf.total_buffered > self.max_buffer_per_dir:
                buf.get_data(fill_gaps=self.fill_gaps)
        return conn
```

Run: `python -m pytest dpkt/stream.py -v -p no:cacheprovider -o "addopts="`
Expected: 18 PASS

- [ ] **Step 3: Commit**

```bash
git add dpkt/stream.py
git commit -m "feat: add callback support and flush to StreamReassembler"
```

---

### Task 7: Integration — dpkt/__init__.py + End-to-End Test

**Files:**
- Modify: `dpkt/__init__.py`

- [ ] **Step 1: Add import to __init__.py**

After `from . import stp` add:
```python
from . import stream
```

- [ ] **Step 2: Write end-to-end integration test**

```python
def test_stream_end_to_end():
    """Full HTTP flow: SYN→DATA→FIN in both directions."""
    reasm = StreamReassembler()

    def make_packet(src_ip, sport, dst_ip, dport, seq, ack, flags, data):
        ip = dpkt.ip.IP(src=src_ip, dst=dst_ip, p=6)
        tcp_pkt = dpkt.tcp.TCP(sport=sport, dport=dport, seq=seq, ack=ack, flags=flags, data=data)
        ip.data = tcp_pkt
        return ip, tcp_pkt

    # Client SYN
    ip, tcp = make_packet(b'\x0a\x00\x00\x01', 12345, b'\x0a\x00\x00\x02', 80, 0, 0, tcp_mod.TH_SYN, b'')
    reasm.feed(ip, tcp)
    # Server SYN-ACK
    ip, tcp = make_packet(b'\x0a\x00\x00\x02', 80, b'\x0a\x00\x00\x01', 12345, 5000, 1, tcp_mod.TH_SYN|tcp_mod.TH_ACK, b'')
    reasm.feed(ip, tcp)
    # Client request (fragmented)
    ip, tcp = make_packet(b'\x0a\x00\x00\x01', 12345, b'\x0a\x00\x00\x02', 80, 0, 5001, tcp_mod.TH_ACK, b'GET /')
    reasm.feed(ip, tcp)
    ip, tcp = make_packet(b'\x0a\x00\x00\x01', 12345, b'\x0a\x00\x00\x02', 80, 5, 5001, tcp_mod.TH_ACK, b' HTTP/1.1\r\n')
    reasm.feed(ip, tcp)
    # Client FIN
    ip, tcp = make_packet(b'\x0a\x00\x00\x01', 12345, b'\x0a\x00\x00\x02', 80, 16, 5001, tcp_mod.TH_ACK|tcp_mod.TH_FIN, b'')
    reasm.feed(ip, tcp)
    # Server response  
    ip, tcp = make_packet(b'\x0a\x00\x00\x02', 80, b'\x0a\x00\x00\x01', 12345, 5000, 17, tcp_mod.TH_ACK, b'HTTP/1.1 200 OK\r\n')
    reasm.feed(ip, tcp)

    conn = reasm.find(src='10.0.0.1', sport=12345)
    assert conn is not None
    request = conn.c2s.get_data()
    response = conn.s2c.get_data()
    assert b'GET / HTTP/1.1' in request
    assert b'200 OK' in response
```

- [ ] **Step 3: Run full test suite**

Run: `python -m pytest dpkt/stream.py -v -p no:cacheprovider -o "addopts="`
Expected: 19 PASS

Run: `python -m pytest dpkt/ -x -q -p no:cacheprovider -o "addopts="`
Expected: all existing tests pass, no regressions

- [ ] **Step 4: Commit**

```bash
git add dpkt/__init__.py dpkt/stream.py
git commit -m "feat: register stream module in dpkt + add end-to-end integration test"
```

---

## Final Verification

```bash
python -m pytest dpkt/ -x -q -p no:cacheprovider -o "addopts="
```
Expected: all tests pass (~505 passed, 0 failures)

```bash
python -c "import dpkt; print(hasattr(dpkt, 'stream')); r = dpkt.stream.StreamReassembler(); print(type(r))"
```
Expected: True, <class 'dpkt.stream.StreamReassembler'>
