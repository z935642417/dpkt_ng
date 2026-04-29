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
