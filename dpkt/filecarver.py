# -*- coding: utf-8 -*-
"""File carving from network captures."""
from __future__ import absolute_import, print_function
import re, base64, quopri, io


class ExtractedFile(object):
    """Represents a file extracted from network traffic."""
    def __init__(self, filename='', content=b'', protocol=''):
        self.filename = filename
        self.content = content if isinstance(content, bytes) else content.encode()
        self.size = len(self.content)
        self.source_protocol = protocol
        self.direction = 'download'
        self.mime_type = ''
        self.metadata = {}

    def __repr__(self):
        return 'ExtractedFile(%s, %d bytes, %s)' % (self.filename, self.size, self.source_protocol)


class MIMEParser(object):
    """Extract attachments from MIME email messages."""

    @staticmethod
    def parse(raw_email):
        """Parse MIME email, return [(filename, content, mime_type), ...]."""
        results = []
        m = re.search(rb'boundary="?([^"\r\n]+)"?', raw_email)
        if not m: return results
        boundary = b'--' + m.group(1)
        parts = raw_email.split(boundary)
        for part in parts:
            if b'Content-Disposition' not in part: continue
            fn_match = re.search(rb'filename="?([^"\r\n]+)"?', part)
            filename = fn_match.group(1).decode('latin-1', errors='replace') if fn_match else 'attachment'
            header_end = part.find(b'\r\n\r\n')
            if header_end < 0: continue
            body = part[header_end+4:]
            body = body.rstrip(b'\r\n').rstrip(b'--').rstrip(b'\r\n')
            # Decode
            encoding = b'identity'
            enc_match = re.search(rb'Content-Transfer-Encoding:\s*(\S+)', part, re.IGNORECASE)
            if enc_match: encoding = enc_match.group(1).lower()
            if encoding == b'base64':
                try:
                    body = re.sub(rb'\s', b'', body)
                    body = base64.b64decode(body)
                except: pass
            elif encoding == b'quoted-printable':
                try:
                    buf = io.BytesIO(); quopri.decode(io.BytesIO(body), buf); body = buf.getvalue()
                except: pass
            mime_type = ''
            mt_match = re.search(rb'Content-Type:\s*([^\r\n;]+)', part, re.IGNORECASE)
            if mt_match: mime_type = mt_match.group(1).decode('latin-1', errors='replace')
            results.append((filename, body, mime_type))
        return results


class FileCarver(object):
    """TCP-stream-aware file carver."""

    def __init__(self):
        self.files = []
        self._streams = {}  # conn_id → {'data': b'', 'protocol': str}
        from . import stream as stream_mod
        self._reasm = stream_mod.StreamReassembler(max_connections=5000)

    def process_packet(self, ip, eth=None):
        """Feed one parsed IP+Eth packet. TCP streams go to reassembler."""
        from . import tcp as tcp_mod, udp as udp_mod
        pkt = ip.data
        if not isinstance(pkt, tcp_mod.TCP): return
        sport, dport = pkt.sport, pkt.dport
        # Feed to stream reassembler
        self._reasm.feed(ip, pkt)
        # Track protocol by port
        conn_id = ('.'.join(str(b) for b in ip.src) if isinstance(ip.src, bytes) else str(ip.src),
                   sport, '.'.join(str(b) for b in ip.dst) if isinstance(ip.dst, bytes) else str(ip.dst), dport)
        proto = self._detect_protocol(sport, dport)
        if conn_id not in self._streams:
            self._streams[conn_id] = {'proto': proto}

    def _detect_protocol(self, sport, dport):
        ports = {sport, dport}
        if 80 in ports or 8080 in ports: return 'http'
        if 21 in ports: return 'ftp'
        if 25 in ports or 587 in ports: return 'smtp'
        if 110 in ports: return 'pop3'
        if 143 in ports or 993 in ports: return 'imap'
        if 445 in ports: return 'smb'
        return 'unknown'

    def carve(self):
        """Extract files from all reassembled streams."""
        for conn_id in self._reasm.connections:
            conn = self._reasm[conn_id]
            data_c2s = conn.c2s.get_data(fill_gaps=False)
            data_s2c = conn.s2c.get_data(fill_gaps=False)
            proto = self._streams.get(conn_id, {}).get('proto', 'unknown')

            if proto == 'http' and data_s2c:
                self._carve_http_response(data_s2c, conn_id, 'download')
            elif proto == 'http' and data_c2s:
                self._carve_http_request(data_c2s, conn_id, 'upload')
            elif proto == 'ftp':
                self._carve_ftp(data_c2s, data_s2c, conn_id)
            elif proto in ('smtp', 'pop3', 'imap'):
                self._carve_email(data_c2s, data_s2c, conn_id, proto)
        return self.files

    def _carve_http_response(self, data, conn_id, direction):
        try:
            header_end = data.find(b'\r\n\r\n')
            if header_end < 0: return
            headers = data[:header_end]
            body = data[header_end+4:]
            # Extract filename
            filename = 'http_download'
            cd = re.search(rb'Content-Disposition:.*filename="?([^"\r\n]+)"?', headers, re.IGNORECASE)
            if cd: filename = cd.group(1).decode('latin-1', errors='replace')
            # Extract Content-Type
            ct = re.search(rb'Content-Type:\s*([^\r\n;]+)', headers, re.IGNORECASE)
            mime = ct.group(1).decode() if ct else ''
            f = ExtractedFile(filename, body, 'http')
            f.direction = direction; f.mime_type = mime
            self.files.append(f)
        except: pass

    def _carve_http_request(self, data, conn_id, direction):
        try:
            if len(data) < 10: return
            header_end = data.find(b'\r\n\r\n')
            if header_end < 0: return
            body = data[header_end+4:]
            if not body: return
            first_line = data[:data.find(b'\r\n')].decode()
            parts = first_line.split(' ')
            if len(parts) < 2: return
            url = parts[1]
            filename = url.split('/')[-1] if '/' in url else 'upload'
            if not filename: filename = 'upload'
            f = ExtractedFile(filename, body, 'http')
            f.direction = 'upload'
            self.files.append(f)
        except: pass

    def _carve_ftp(self, data_c2s, data_s2c, conn_id):
        # Simple: extract filename from RETR/STOR in control channel
        for direction, data in [('download', data_s2c), ('upload', data_c2s)]:
            if data and len(data) > 10:
                m = re.search(rb'(?:RETR|STOR)\s+(\S+)', data, re.IGNORECASE)
                filename = m.group(1).decode('latin-1', errors='replace') if m else 'ftp_file'
                f = ExtractedFile(filename, data, 'ftp')
                f.direction = direction
                self.files.append(f)
                return

    def _carve_email(self, data_c2s, data_s2c, conn_id, proto):
        for data in (data_c2s, data_s2c):
            if not data or len(data) < 50: continue
            attachments = MIMEParser.parse(data)
            for filename, content, mime_type in attachments:
                f = ExtractedFile(filename, content, proto)
                f.mime_type = mime_type; self.files.append(f)

    def export_files(self, directory):
        import os
        os.makedirs(directory, exist_ok=True)
        for i, f in enumerate(self.files):
            safe_name = re.sub(r'[^\w\-.]', '_', f.filename) or 'file_%d' % i
            path = os.path.join(directory, safe_name)
            with open(path, 'wb') as fh:
                fh.write(f.content)


# ---- Tests ----
def test_extracted_file():
    f = ExtractedFile('test.txt', b'hello', 'http')
    assert f.filename == 'test.txt'
    assert f.size == 5
    assert f.source_protocol == 'http'

def test_mime_parser():
    email = (b'From: a@b.com\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary="boundary"\r\n\r\n'
             b'--boundary\r\nContent-Disposition: attachment; filename="doc.pdf"\r\n'
             b'Content-Type: application/pdf\r\nContent-Transfer-Encoding: base64\r\n\r\n'
             b'SGVsbG8=\r\n--boundary--')
    results = MIMEParser.parse(email)
    assert len(results) == 1
    assert results[0][0] == 'doc.pdf'
    assert results[0][1] == b'Hello'

def test_file_carver_init():
    c = FileCarver()
    assert c.files == []
    assert c._detect_protocol(80, 12345) == 'http'
    assert c._detect_protocol(21, 12345) == 'ftp'
