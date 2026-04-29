# -*- coding: utf-8 -*-
"""Server Message Block version 2."""
from __future__ import print_function
from __future__ import absolute_import

from . import dpkt

# SMB2 Flags
SMB2_FLAGS_SERVER_TO_REDIR = 0x00000001
SMB2_FLAGS_ASYNC_COMMAND = 0x00000002
SMB2_FLAGS_RELATED_OPERATIONS = 0x00000004
SMB2_FLAGS_SIGNED = 0x00000008
SMB2_FLAGS_PRIORITY_MASK = 0x00000070
SMB2_FLAGS_DFS_OPERATIONS = 0x10000000
SMB2_FLAGS_REPLAY_OPERATION = 0x20000000

# SMB2 Command codes
SMB2_CMD_NEGOTIATE = 0x0000
SMB2_CMD_SESSION_SETUP = 0x0001
SMB2_CMD_LOGOFF = 0x0002
SMB2_CMD_TREE_CONNECT = 0x0003
SMB2_CMD_TREE_DISCONNECT = 0x0004
SMB2_CMD_CREATE = 0x0005
SMB2_CMD_CLOSE = 0x0006
SMB2_CMD_FLUSH = 0x0007
SMB2_CMD_READ = 0x0008
SMB2_CMD_WRITE = 0x0009
SMB2_CMD_LOCK = 0x000A
SMB2_CMD_IOCTL = 0x000B
SMB2_CMD_CANCEL = 0x000C
SMB2_CMD_ECHO = 0x000D
SMB2_CMD_QUERY_DIRECTORY = 0x000E
SMB2_CMD_CHANGE_NOTIFY = 0x000F
SMB2_CMD_QUERY_INFO = 0x0010
SMB2_CMD_SET_INFO = 0x0011
SMB2_CMD_OPLOCK_BREAK = 0x0012


class SMB2(dpkt.Packet):
    """SMB2 Protocol Packet.

    Attributes:
        __hdr__: SMB2 64-byte fixed header
    """
    __byte_order__ = '<'
    __hdr__ = [
        ('proto', '4s', b'\xfeSMB'),
        ('hdr_len', 'H', 64),
        ('credit_charge', 'H', 0),
        ('_status', 'I', 0),
        ('cmd', 'H', 0),
        ('credit_req', 'H', 0),
        ('_flags_val', 'I', 0),
        ('next_cmd', 'I', 0),
        ('mid', 'Q', 0),
        ('pid', 'I', 0),
        ('tid', 'I', 0),
        ('sid', 'Q', 0),
        ('sig', '16s', b'\x00' * 16),
    ]
    __bit_fields__ = {
        '_flags_val': (
            ('_rsv_hi', 2),
            ('replay', 1),
            ('dfs', 1),
            ('_rsv_mid', 21),
            ('priority', 3),
            ('signed', 1),
            ('related', 1),
            ('async', 1),
            ('response', 1),
        ),
    }


def test_smb2_header():
    """Verify SMB2 64-byte header unpack."""
    from binascii import unhexlify
    buf = unhexlify(
        'fe534d424000' + '0000' * 29
    )
    smb2 = SMB2(buf)
    assert smb2.proto == b'\xfeSMB'
    assert smb2.hdr_len == 64
    assert smb2.cmd == 0
    assert len(bytes(smb2)) == 64


def test_smb2_flags():
    """Test SMB2 flag bit fields."""
    smb2 = SMB2()
    assert smb2.response == 0
    smb2.response = 1
    assert smb2.response == 1
    assert (smb2._flags_val & 1) == 1
    smb2.signed = 1
    assert smb2.signed == 1
    assert smb2.response == 1
    smb2.dfs = 1
    assert smb2.dfs == 1
    smb2.replay = 1
    assert smb2.replay == 1
    setattr(smb2, 'async', 1)
    assert getattr(smb2, 'async') == 1
    smb2.related = 1
    assert smb2.related == 1
    assert smb2.response == 1
    assert smb2.signed == 1


def test_smb2_roundtrip():
    """Test SMB2 pack → unpack → bytes."""
    smb2 = SMB2(cmd=SMB2_CMD_READ, mid=1, pid=0x1234, tid=0x5678, sid=0x9ABC)
    data = bytes(smb2)
    assert len(data) == 64
    parsed = SMB2(data)
    assert parsed.cmd == SMB2_CMD_READ
    assert parsed.mid == 1
    assert parsed.pid == 0x1234
    assert parsed.tid == 0x5678
    assert parsed.sid == 0x9ABC
