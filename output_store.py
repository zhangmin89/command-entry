"""Drain every byte, retain only bounded redacted text; never persist raw output."""
import codecs
import re
import threading
import uuid


def redact_line(line):
    if re.search(r'(?i)(?:password|passwd|api[_-]?key|access[_-]?token|refresh[_-]?token|authorization|cookie|secret)\s*[=:]', line):
        return '[REDACTED credential line]\n'
    line = re.sub(r'(?i)\bBearer\s+\S+', '[REDACTED bearer]', line)
    return re.sub(r'\b(?:sk-[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9_]{16,}|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)', '[REDACTED]', line)


class Capture:
    def __init__(self, path, encoding='utf-8', quota=1048576):
        self.path, self.quota = path, quota
        self.total = self.retained = self.decoding_errors = self.missing_lines = 0
        self.redacted = False
        self.complete = False
        self.storage_error = None
        self.pending, self.head, self.tail = '', '', ''
        self.line_number = 0
        self.missing_line_ranges = []
        self.discard_line = self.private = False
        error_name = 'command_entry_' + uuid.uuid4().hex
        def decode_error(error):
            self.decoding_errors += 1
            return ('\ufffd', error.end)
        codecs.register_error(error_name, decode_error)
        self.decoder = codecs.getincrementaldecoder(encoding)(errors=error_name)
        self.file = None
        if path is not None:
            try:
                self.file = path.open('xb')
            except OSError as error:
                self.storage_error = type(error).__name__

    def accept_line(self, line):
        if '-----BEGIN ' in line and 'PRIVATE KEY-----' in line:
            self.private = True
        if self.private:
            if '-----END ' in line and 'PRIVATE KEY-----' in line:
                self.private = False
            safe = '[REDACTED private key material]\n'
        else:
            safe = redact_line(line)
        self.redacted |= safe != line
        if len(self.head) < 512:
            self.head += safe[:512-len(self.head)]
        self.tail = (self.tail + safe)[-512:]
        raw = safe.encode('utf-8')
        if self.file is not None and self.retained + len(raw) <= self.quota:
            try:
                self.file.write(raw)
                self.file.flush()
                self.retained += len(raw)
            except OSError as error:
                self.storage_error = type(error).__name__
                self.file.close()
                self.file = None
                self.missing_lines += 1
                self.mark_missing(self.line_number)
        else:
            self.missing_lines += 1
            self.mark_missing(self.line_number)

    def mark_missing(self, line):
        if self.missing_line_ranges and self.missing_line_ranges[-1][1] + 1 >= line:
            self.missing_line_ranges[-1][1] = line
        else:
            self.missing_line_ranges.append([line,line])

    def feed(self, data, final=False):
        self.total += len(data)
        text = self.decoder.decode(data, final=final)
        for fragment in text.splitlines(keepends=True):
            ended = fragment.endswith(('\n','\r'))
            if not self.discard_line:
                self.pending += fragment
                if len(self.pending) > 16384:
                    self.pending = ''
                    self.discard_line = True
                    self.missing_lines += 1
                    self.mark_missing(self.line_number+1)
            if ended:
                self.line_number += 1
                if not self.discard_line:
                    self.accept_line(self.pending)
                self.pending = ''
                self.discard_line = False
        if final:
            if self.pending and not self.discard_line:
                self.line_number += 1
                self.accept_line(self.pending)
            self.pending = ''
            self.complete = True
            if self.file:
                self.file.close()
                self.file = None

    def drain(self, pipe):
        try:
            while True:
                chunk = pipe.read1(8192)
                if not chunk:
                    break
                self.feed(chunk)
        finally:
            self.feed(b'', final=True)
            pipe.close()

    def start(self, pipe):
        self.thread = threading.Thread(target=self.drain, args=(pipe,), daemon=True)
        self.thread.start()

    def metadata(self):
        return {'captured_bytes':self.total, 'capture_complete':self.complete,
                'retained_utf8_bytes':self.retained, 'retained_view_complete':self.complete and self.missing_lines == 0,
                'missing_lines':self.missing_lines, 'decoding_loss':self.decoding_errors > 0,
                'missing_decoded_line_ranges':self.missing_line_ranges,
                'decode_error_count':self.decoding_errors, 'redacted':self.redacted,
                'raw_bytes_persisted':False, 'storage_error':self.storage_error,
                'output_reference':self.path.name if self.path else None,
                'preview_head':self.head, 'preview_tail':self.tail,
                'preview_complete':self.complete and self.total <= 512 and self.missing_lines == 0}
