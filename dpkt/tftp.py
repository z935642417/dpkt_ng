# $Id: tftp.py 23 2006-11-08 15:45:33Z dugsong $
# -*- coding: utf-8 -*-
"""Trivial File Transfer Protocol."""
from __future__ import print_function
from __future__ import absolute_import

import struct

from . import dpkt

# Opcodes
OP_RRQ = 1  # read request
OP_WRQ = 2  # write request
OP_DATA = 3  # data packet
OP_ACK = 4  # acknowledgment
OP_ERR = 5  # error code
OP_OACK = 6  # option acknowledgment

# RFC 2347 option names
TFTP_OPT_BLKSIZE = 'blksize'
TFTP_OPT_TSIZE = 'tsize'
TFTP_OPT_TIMEOUT = 'timeout'
TFTP_OPT_MULTICAST = 'multicast'
TFTP_OPT_WINDOWSIZE = 'windowsize'

# Error codes
EUNDEF = 0  # not defined
ENOTFOUND = 1  # file not found
EACCESS = 2  # access violation
ENOSPACE = 3  # disk full or allocation exceeded
EBADOP = 4  # illegal TFTP operation
EBADID = 5  # unknown transfer ID
EEXISTS = 6  # file already exists
ENOUSER = 7  # no such user


class TFTP(dpkt.Packet):
    """Trivial File Transfer Protocol.

    Trivial File Transfer Protocol (TFTP) is a simple lockstep File Transfer Protocol which allows a client to get
    a file from or put a file onto a remote host. One of its primary uses is in the early stages of nodes booting
    from a local area network. TFTP has been used for this application because it is very simple to implement.

    Attributes:
        __hdr__: Header fields of TFTP.
            opcode: Operation Code (2 bytes)
    """

    __hdr__ = (('opcode', 'H', 1), )

    def __init__(self, *args, **kwargs):
        self.options = {}
        self.strict = False
        super(TFTP, self).__init__(*args, **kwargs)

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        if self.opcode in (OP_RRQ, OP_WRQ):
            l_ = self.data.split(b'\x00')
            self.filename = l_[0] if len(l_) > 0 else b''
            self.mode = l_[1] if len(l_) > 1 else b''
            self.options = {}
            for i in range(2, len(l_) - 1, 2):
                key = l_[i]
                val = l_[i + 1] if i + 1 < len(l_) else b''
                if not key:
                    if self.strict:
                        raise dpkt.UnpackError('empty option key in TFTP')
                    continue
                self.options[key] = val
            # Check for orphaned last key in lenient mode
            if len(l_) > 2 and (len(l_) - 2) % 2 == 1:
                last_key = l_[-1]
                if last_key and last_key not in self.options:
                    if self.strict:
                        raise dpkt.UnpackError('missing option value in TFTP')
                    self.options[last_key] = b''
            self.data = b''
        elif self.opcode == OP_OACK:
            l_ = self.data.split(b'\x00')
            if len(l_) > 1:
                self.options = {}
                for i in range(0, len(l_) - 1, 2):
                    key = l_[i]
                    val = l_[i + 1] if i + 1 < len(l_) else b''
                    if key:
                        self.options[key] = val
                self.data = b''
        elif self.opcode in (OP_DATA, OP_ACK):
            self.block = struct.unpack('>H', self.data[:2])[0]
            self.data = self.data[2:]
        elif self.opcode == OP_ERR:
            self.errcode = struct.unpack('>H', self.data[:2])[0]
            self.errmsg = self.data[2:].split(b'\x00')[0]
            self.data = b''

    def __repr__(self):
        op_names = {OP_RRQ: 'RRQ', OP_WRQ: 'WRQ', OP_DATA: 'DATA',
                    OP_ACK: 'ACK', OP_ERR: 'ERR', OP_OACK: 'OACK'}
        parts = [op_names.get(self.opcode, 'OP(%d)' % self.opcode)]
        if hasattr(self, 'filename') and self.filename:
            parts.append('file=%s' % self.filename)
        if self.options:
            parts.append('opts=%s' % self.options)
        return 'TFTP(' + ', '.join(parts) + ')'

    def __len__(self):
        return len(bytes(self))

    def __bytes__(self):
        if self.opcode in (OP_RRQ, OP_WRQ):
            parts = [self.filename, self.mode]
            for key, val in self.options.items():
                parts.append(key)
                parts.append(val)
            s = b'\x00'.join(parts) + b'\x00'
        elif self.opcode == OP_OACK:
            if self.options:
                parts = []
                for key, val in self.options.items():
                    parts.append(key)
                    parts.append(val)
                s = b'\x00'.join(parts) + b'\x00'
            else:
                s = b''
        elif self.opcode in (OP_DATA, OP_ACK):
            s = struct.pack('>H', self.block)
        elif self.opcode == OP_ERR:
            s = struct.pack('>H', self.errcode) + (b'%s\x00' % self.errmsg)
        else:
            s = b''
        return self.pack_hdr() + s + self.data

    def get_option(self, name, default=None):
        return self.options.get(name, default)


def test_op_rrq():
    from binascii import unhexlify
    buf = unhexlify(
        '0001'    # opcode (OP_RRQ)
        '726663313335302e747874'  # filename (rfc1350.txt)
        '00'                      # null terminator
        '6f63746574'              # mode (octet)
        '00'                      # null terminator
    )
    tftp = TFTP(buf)
    assert tftp.filename == b'rfc1350.txt'
    assert tftp.mode == b'octet'
    assert bytes(tftp) == buf
    assert len(tftp) == len(buf)


def test_op_data():
    from binascii import unhexlify
    buf = unhexlify(
        '0003'    # opcode (OP_DATA)
        '0001'    # block
        '0a0a4e6574776f726b20576f726b696e672047726f7570'
    )
    tftp = TFTP(buf)
    assert tftp.block == 1
    assert tftp.data == b'\x0a\x0aNetwork Working Group'
    assert bytes(tftp) == buf
    assert len(tftp) == len(buf)


def test_op_err():
    from binascii import unhexlify
    buf = unhexlify(
        '0005'   # opcode (OP_ERR)
        '0007'   # errcode (ENOUSER)
        '0a0a4e6574776f726b20576f726b696e672047726f757000'
    )
    tftp = TFTP(buf)
    assert tftp.errcode == ENOUSER
    assert tftp.errmsg == b'\x0a\x0aNetwork Working Group'
    assert tftp.data == b''
    assert bytes(tftp) == buf


def test_op_other():
    from binascii import unhexlify
    buf = unhexlify(
        '0006'     # opcode (doesn't exist)
        'abcdef'   # trailing data
    )
    tftp = TFTP(buf)
    assert tftp.opcode == 6
    assert bytes(tftp) == buf
    assert tftp.data == unhexlify('abcdef')


def test_op_wrq_with_options():
    """WRQ with blksize and tsize options."""
    buf = (b'\x00\x02'
           b'file.bin\x00'
           b'octet\x00'
           b'blksize\x00' b'1024\x00'
           b'tsize\x00' b'0\x00')
    tftp = TFTP(buf)
    assert tftp.opcode == OP_WRQ
    assert tftp.filename == b'file.bin'
    assert tftp.mode == b'octet'
    assert tftp.options == {b'blksize': b'1024', b'tsize': b'0'}


def test_op_oack():
    """OACK packet with negotiated options."""
    buf = (b'\x00\x06'
           b'blksize\x00' b'1024\x00'
           b'tsize\x00' b'4096\x00')
    tftp = TFTP(buf)
    assert tftp.opcode == OP_OACK
    assert tftp.options == {b'blksize': b'1024', b'tsize': b'4096'}


def test_op_options_get_option():
    """get_option() helper method."""
    buf = (b'\x00\x01file.txt\x00octet\x00blksize\x008192\x00')
    tftp = TFTP(buf)
    assert tftp.get_option(b'blksize') == b'8192'
    assert tftp.get_option(b'tsize') is None
    assert tftp.get_option(b'tsize', b'0') == b'0'


def test_tftp_roundtrip_options():
    """Construct TFTP with options → bytes → parse → verify."""
    tftp = TFTP(opcode=OP_WRQ, filename=b'upload.bin', mode=b'octet',
                options={b'blksize': b'4096', b'timeout': b'10'})
    data = bytes(tftp)
    parsed = TFTP(data)
    assert parsed.opcode == OP_WRQ
    assert parsed.filename == b'upload.bin'
    assert parsed.get_option(b'blksize') == b'4096'
    assert parsed.get_option(b'timeout') == b'10'


def test_lenient_missing_null():
    """Lenient mode: accept truncated option without final null."""
    buf = (b'\x00\x01file.txt\x00octet\x00blksize\x001024')
    tftp = TFTP(buf)
    assert tftp.filename == b'file.txt'
    assert tftp.options == {b'blksize': b'1024'}


def test_strict_missing_null():
    """Strict mode: raise UnpackError on malformed packet."""
    buf = (b'\x00\x01file.txt\x00octet\x00blksize')
    tftp = TFTP()
    tftp.strict = True
    try:
        tftp.unpack(buf)
        assert False, "should have raised"
    except dpkt.UnpackError:
        pass


def test_tftp_repr():
    """__repr__ shows opcode name, filename, options."""
    buf = (b'\x00\x01file.txt\x00octet\x00blksize\x001024\x00')
    tftp = TFTP(buf)
    r = repr(tftp)
    assert 'RRQ' in r
    assert 'file.txt' in r
