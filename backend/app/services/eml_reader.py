"""Bounded, memory-only EML reader. Budgets are v1 implementation limits."""
from __future__ import annotations

from dataclasses import dataclass, field
from email import policy
from email.message import EmailMessage
from email.parser import BytesHeaderParser
from html.parser import HTMLParser
import os
from pathlib import Path
import re
import stat

from app.core.exceptions import InvalidScanInputError
from app.core.url_utils import MAX_LINKS, MAX_URL_LENGTH, parse_url

MAX_BYTES = 1024 * 1024
MAX_PARTS = 64
MAX_DEPTH = 8
MAX_HEADER_BYTES = 32 * 1024
MAX_HEADER_LINES = 256
MAX_TOKENS = 8192
MAX_BODY_CHARS = 128 * 1024
EXPLICIT = re.compile(r"""(?i)(?<![\w:/])https?://[^\s<>"']+""")


class ImportErrorCode(ValueError):
    """Only fixed reason codes may cross the import boundary."""


@dataclass(repr=False)
class MailParts:
    headers: EmailMessage | None = None
    text: list[str] = field(default_factory=list)
    targets: dict[str, str] = field(default_factory=dict)
    coverage: set[str] = field(default_factory=set)
    part_count: int = 0
    tokens: int = 0
    chars: int = 0

    def link(self, value):
        if not value.lower().startswith(('http://', 'https://')):
            self.coverage.add('email_link_scheme_unsupported')
            return
        if len(value) > MAX_URL_LENGTH:
            raise ImportErrorCode('email_import_limit_exceeded')
        try:
            canonical = parse_url(value).canonical
        except InvalidScanInputError:
            self.coverage.add('email_link_invalid')
            return
        self.targets.setdefault(canonical, value)
        if len(self.targets) > MAX_LINKS:
            raise ImportErrorCode('email_import_limit_exceeded')


class Anchors(HTMLParser):
    """Only anchor destinations. No renderer, URL joining, or resource callbacks."""
    def __init__(self, parts):
        super().__init__()
        self.parts = parts
        self.href = None
        self.label = []

    def handle_starttag(self, tag, attrs):
        if tag == 'a':
            self.href = dict(attrs).get('href')
            self.label.clear()
            if self.href:
                self.parts.link(self.href)

    def handle_data(self, data):
        if self.href:
            self.label.append(data)

    def handle_endtag(self, tag):
        if tag == 'a' and self.href:
            label = ''.join(self.label).strip()
            if EXPLICIT.fullmatch(label) and EXPLICIT.fullmatch(self.href):
                try:
                    if parse_url(label).host != parse_url(self.href).host:
                        self.parts.coverage.add('email_anchor_host_differs')
                except InvalidScanInputError:
                    pass
            self.href = None
            self.label.clear()


def _part(raw, depth, result):
    result.part_count += 1
    if result.part_count > MAX_PARTS or depth > MAX_DEPTH:
        raise ImportErrorCode('email_import_limit_exceeded')
    header, sep, payload = raw.partition(b'\n\n')
    if not sep:
        raise ImportErrorCode('email_malformed_mime')
    if len(header) > MAX_HEADER_BYTES or header.count(b'\n') + 1 > MAX_HEADER_LINES:
        raise ImportErrorCode('email_import_limit_exceeded')
    msg = BytesHeaderParser(policy=policy.default).parsebytes(header + b'\n\n')
    if msg.defects or any(len(msg.get_all(key, [])) > 1 for key in
                          ('Content-Type', 'Content-Transfer-Encoding', 'Content-Disposition')):
        raise ImportErrorCode('email_malformed_mime')
    if depth == 0:
        result.headers = msg
    kind = msg.get_content_type()
    if msg.get_filename() or msg.get_content_disposition() == 'attachment' or kind.startswith('message/'):
        result.coverage.add('email_attachment_skipped')
        return
    if kind in ('multipart/mixed', 'multipart/related', 'multipart/alternative'):
        boundary = msg.get_boundary()
        if not boundary:
            raise ImportErrorCode('email_malformed_mime')
        pattern = rb'(?m)^--' + re.escape(boundary.encode('ascii')) + rb'(--)?[ \t]*(?:\n|$)'
        start = None
        for marker in re.finditer(pattern, payload):
            if start is not None:
                _part(payload[start:marker.start()], depth + 1, result)
            if marker[1]:
                if start is None:
                    raise ImportErrorCode('email_malformed_mime')
                return
            start = marker.end()
        raise ImportErrorCode('email_malformed_mime')
    if kind not in ('text/plain', 'text/html'):
        result.coverage.add('email_body_unsupported')
        return
    if str(msg.get('Content-Transfer-Encoding', '7bit')).lower() not in (
            'base64', 'quoted-printable', '7bit', '8bit', 'binary'):
        result.coverage.add('email_encoding_unsupported')
        return
    msg.set_payload(payload)
    decoded = msg.get_payload(decode=True).decode(msg.get_content_charset() or 'ascii')
    if msg.defects:
        raise ImportErrorCode('email_malformed_mime')
    result.chars += len(decoded)
    result.tokens += len(decoded.split())
    if result.chars > MAX_BODY_CHARS or result.tokens > MAX_TOKENS:
        raise ImportErrorCode('email_import_limit_exceeded')
    if kind == 'text/html':
        html = Anchors(result)
        html.feed(decoded)
        html.close()
        # HTML prose/quotation boundaries are not reviewed for payment rules.
        result.coverage.add('email_html_text_not_checked')
    else:
        result.text.append(decoded)
        for token in decoded.split():
            if token.lower().startswith('data:'):
                result.coverage.add('email_link_scheme_unsupported')
                continue
            for match in EXPLICIT.finditer(token):
                result.link(match[0].rstrip('.,;)'))


def read_eml(path: Path) -> MailParts:
    """Read one selected regular local file, skip attachment bodies before decoding."""
    path = Path(path)
    if path.suffix.lower() != '.eml' or str(path).startswith(('//', '\\\\')):
        raise ImportErrorCode('email_local_eml_required')
    try:
        path = path.absolute()
        if os.name == 'nt':
            import ctypes
            if ctypes.windll.kernel32.GetDriveTypeW(path.anchor) not in (2, 3, 6):
                raise ImportErrorCode('email_local_eml_required')
        for entry in (*reversed(path.parents), path):
            status = entry.lstat()
            if stat.S_ISLNK(status.st_mode) or getattr(status, 'st_file_attributes', 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT:
                raise ImportErrorCode('email_local_eml_required')
        if not stat.S_ISREG(status.st_mode):
            raise ImportErrorCode('email_local_eml_required')
        with path.open('rb') as stream:
            raw = stream.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise ImportErrorCode('email_import_limit_exceeded')
        result = MailParts()
        _part(raw.replace(b'\r\n', b'\n'), 0, result)
        return result
    except ImportErrorCode:
        raise
    except (OSError, ValueError, LookupError, RecursionError, IndexError) as exc:
        raise ImportErrorCode('email_import_unreadable') from None
