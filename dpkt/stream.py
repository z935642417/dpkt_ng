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
        items = []  # [(dir, rel_seq, ack, data), ...]
        # c2s contiguous
        if self.c2s.contiguous:
            base = self.c2s.next_seq - len(self.c2s.contiguous)
            items.append(('c2s', base, 0, bytes(self.c2s.contiguous)))
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

        # Sort: lower seq first; c2s before s2c when no ack relationship
        def sort_key(item):
            direction, rel_seq, ack, data = item
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
    buf.feed(seq=1, ack=0, payload=b'HELLO', flags=tcp_mod.TH_ACK)
    assert buf.get_data() == b'HELLO'
    assert buf.next_seq == 6

def test_direction_buffer_out_of_order():
    """Out-of-order segments are buffered and delivered when gaps fill."""
    buf = DirectionBuffer()
    buf.feed(seq=0, ack=0, payload=b'', flags=tcp_mod.TH_SYN)
    # Segment at seq=4 arrives first (gap at 1-3)
    buf.feed(seq=4, ack=0, payload=b'LO', flags=tcp_mod.TH_ACK)
    assert buf.get_data() == b''  # gap exists
    assert len(buf.segments) == 1
    # Segment at seq=1 fills the gap
    buf.feed(seq=1, ack=0, payload=b'HEL', flags=tcp_mod.TH_ACK)
    assert buf.get_data() == b'HELLO'
    assert len(buf.segments) == 0


def test_direction_buffer_overlap():
    """Retransmitted/overlapping data is deduplicated."""
    buf = DirectionBuffer()
    buf.feed(seq=0, ack=0, payload=b'', flags=tcp_mod.TH_SYN)
    buf.feed(seq=1, ack=0, payload=b'HELLO', flags=tcp_mod.TH_ACK)
    buf.feed(seq=1, ack=0, payload=b'HELLO', flags=tcp_mod.TH_ACK)  # full retransmit
    assert buf.get_data() == b'HELLO'
    assert buf.get_data() == b''  # nothing extra


def test_direction_buffer_partial_overlap():
    """Partially overlapping segment: new bytes after overlap are kept."""
    buf = DirectionBuffer()
    buf.feed(seq=0, ack=0, payload=b'', flags=tcp_mod.TH_SYN)
    buf.feed(seq=1, ack=0, payload=b'HELLO', flags=tcp_mod.TH_ACK)
    buf.get_data()
    # Retransmit with extra data appended
    buf.feed(seq=3, ack=0, payload=b'LLOWORLD', flags=tcp_mod.TH_ACK)
    assert buf.get_data() == b'WORLD'


def test_direction_buffer_fin_complete():
    """is_complete only when all bytes between SYN and FIN received."""
    buf = DirectionBuffer()
    buf.feed(seq=0, ack=0, payload=b'', flags=tcp_mod.TH_SYN)
    assert not buf.is_complete
    buf.feed(seq=1, ack=0, payload=b'DATA', flags=tcp_mod.TH_ACK)
    assert not buf.is_complete  # FIN not yet seen
    buf.feed(seq=5, ack=0, payload=b'', flags=tcp_mod.TH_ACK | tcp_mod.TH_FIN)
    assert buf.is_complete  # all bytes between SYN(0) and FIN(4) contiguous


def test_direction_buffer_fin_with_gap():
    """FIN seen but gap remains → not complete."""
    buf = DirectionBuffer()
    buf.feed(seq=0, ack=0, payload=b'', flags=tcp_mod.TH_SYN)
    buf.feed(seq=6, ack=0, payload=b'DATA', flags=tcp_mod.TH_ACK)
    assert not buf.is_complete
    buf.feed(seq=10, ack=0, payload=b'', flags=tcp_mod.TH_ACK | tcp_mod.TH_FIN)
    assert not buf.is_complete  # gap 0-4
    buf.feed(seq=1, ack=0, payload=b'HELLO', flags=tcp_mod.TH_ACK)
    assert buf.is_complete  # now all bytes received


def test_direction_buffer_flush():
    """flush() outputs all data even with gaps."""
    buf = DirectionBuffer()
    buf.feed(seq=0, ack=0, payload=b'', flags=tcp_mod.TH_SYN)
    buf.feed(seq=1, ack=0, payload=b'AA', flags=tcp_mod.TH_ACK)
    buf.feed(seq=6, ack=0, payload=b'BB', flags=tcp_mod.TH_ACK)
    result = buf.get_data(fill_gaps=True)
    assert result == b'AA\x00\x00\x00BB'
    assert buf.total_buffered == 0


def test_direction_buffer_flush_no_fill():
    """flush(fill_gaps=False) only outputs contiguous data."""
    buf = DirectionBuffer()
    buf.feed(seq=0, ack=0, payload=b'', flags=tcp_mod.TH_SYN)
    buf.feed(seq=1, ack=0, payload=b'AA', flags=tcp_mod.TH_ACK)
    buf.feed(seq=6, ack=0, payload=b'BB', flags=tcp_mod.TH_ACK)
    assert buf.get_data() == b'AA'
    assert buf.get_data() == b''
    assert len(buf.segments) == 1  # BB still buffered


def test_connection_routing():
    """Connection routes packets to correct direction based on sport."""
    conn = Connection(src_ip='10.0.0.1', src_port=12345, dst_ip='10.0.0.2', dst_port=445)
    # SYN from client
    conn.c2s.feed(seq=100, ack=0, payload=b'', flags=tcp_mod.TH_SYN)
    conn.c2s.feed(seq=101, ack=0, payload=b'CMD', flags=tcp_mod.TH_ACK)
    # SYN from server
    conn.s2c.feed(seq=5000, ack=0, payload=b'', flags=tcp_mod.TH_SYN)
    conn.s2c.feed(seq=5001, ack=0, payload=b'RSP', flags=tcp_mod.TH_ACK)
    assert conn.c2s.get_data() == b'CMD'
    assert conn.s2c.get_data() == b'RSP'


def test_connection_merged_ordering():
    """merged_data() orders by seq/ack causality."""
    conn = Connection(src_ip='10.0.0.1', src_port=12345, dst_ip='10.0.0.2', dst_port=445)
    # Client sends request
    conn.c2s.feed(seq=0, ack=0, payload=b'', flags=tcp_mod.TH_SYN)
    conn.c2s.feed(seq=1, ack=0, payload=b'GET', flags=tcp_mod.TH_ACK)
    # Server sends response
    conn.s2c.feed(seq=0, ack=0, payload=b'', flags=tcp_mod.TH_SYN)
    conn.s2c.feed(seq=1, ack=0, payload=b'HTTP', flags=tcp_mod.TH_ACK)
    merged = conn.merged_data()
    assert merged == b'GETHTTP'


def test_connection_properties():
    """conn_id and is_closed properties."""
    conn = Connection(src_ip='10.0.0.1', src_port=12345, dst_ip='10.0.0.2', dst_port=80)
    assert conn.conn_id == ('10.0.0.1', 12345, '10.0.0.2', 80)
    assert not conn.is_closed
