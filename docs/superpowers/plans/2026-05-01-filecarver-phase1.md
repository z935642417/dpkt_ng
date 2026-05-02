# File Carving Phase 1 — Design + Implementation Plan

**Goal:** Extract files from HTTP, FTP, and MIME emails in PCAP captures using TCP stream reassembly.

**Architecture:** ExtractedFile model → protocol extractors (HTTP/FTP/MIME) → FileCarver dispatcher.

**Files:** `dpkt/filecarver.py` ~350 lines | 3 tasks | ~6 tests

---

### Task 1: ExtractedFile model + MIME parser framework

```python
class ExtractedFile:
    def __init__(self, filename='', content=b'', protocol=''):
        self.filename=filename; self.content=content; self.size=len(content)
        self.source_protocol=protocol; self.direction='download'
        self.mime_type=''; self.metadata={}

class MIMEParser:
    @staticmethod
    def parse(raw_email):
        """Extract attachments from MIME email. Returns [(filename, content, mime_type), ...]."""
        import re, base64, quopri
        results = []; boundary = b''
        # Find boundary
        m = re.search(rb'boundary="?([^"\r\n]+)"?', raw_email)
        if not m: return results
        boundary = b'--' + m.group(1)
        parts = raw_email.split(boundary)
        for part in parts:
            if b'Content-Disposition' not in part: continue
            # Extract filename
            fn_match = re.search(rb'filename="?([^"\r\n]+)"?', part)
            filename = fn_match.group(1).decode('latin-1') if fn_match else 'attachment'
            # Extract content
            header_end = part.find(b'\r\n\r\n')
            if header_end < 0: continue
            body = part[header_end+4:].rstrip(b'\r\n--')
            # Decode transfer encoding
            encoding = b'identity'
            enc_match = re.search(rb'Content-Transfer-Encoding:\s*(\S+)', part, re.IGNORECASE)
            if enc_match: encoding = enc_match.group(1).lower()
            if encoding == b'base64':
                try: body = base64.b64decode(body)
                except: pass
            elif encoding == b'quoted-printable':
                import io; buf = io.BytesIO(); quopri.decode(io.BytesIO(body), buf); body = buf.getvalue()
            # Detect MIME type
            mime_type = ''
            mt_match = re.search(rb'Content-Type:\s*([^\r\n;]+)', part, re.IGNORECASE)
            if mt_match: mime_type = mt_match.group(1).decode('latin-1')
            results.append((filename, body, mime_type))
        return results
```

Test: simple multipart email with base64 attachment. Commit: `feat: add ExtractedFile model and MIME parser`

---

### Task 2: HTTP + FTP extractors + FileCarver framework

Extractors use dpkt.stream.StreamReassembler for TCP. Protocol dispatch by port.

HTTP (80/8080): parse headers for Content-Disposition, extract body.
FTP (21 + data ports): control channel for filename, data channel for content.

Commit: `feat: add HTTP and FTP file extractors with StreamReassembler`

---

### Task 3: Integration + export_files + full verification

`FileCarver.carve()` iterates all streams, dispatches to extractors. `export_files(dir)` writes files to disk. Register in `__init__.py`. ~617 PASS.
