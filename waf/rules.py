"""Bounded canonicalization and structural detectors. These are not a CRS engine."""
import html
import re
import unicodedata
from dataclasses import dataclass
from html.parser import HTMLParser
from urllib.parse import unquote_plus


@dataclass(frozen=True)
class DetectionRule:
    rule_id: str
    category: str
    score: int
    description: str


RULES = [
    DetectionRule('SQLI-001', 'sql_injection', 6, 'SQL sequences, comparisons, stacked queries and delay functions.'),
    DetectionRule('XSS-001', 'xss', 6, 'Executable HTML elements, event attributes and unsafe URL schemes.'),
    DetectionRule('TRAV-001', 'path_traversal', 6, 'Canonical traversal segments and sensitive file paths.'),
    DetectionRule('CMD-001', 'command_injection', 6, 'Shell command substitution and chained command execution.'),
]


def normalize_for_detection(value: str) -> str:
    normalized = unicodedata.normalize('NFKC', value)
    for _ in range(4):
        decoded = html.unescape(unquote_plus(normalized))
        if decoded == normalized:
            break
        normalized = decoded
    return normalized.replace('\x00', '').casefold()


def _sql(value):
    keywords = {'union', 'select', 'from', 'and', 'or', 'sleep', 'benchmark', 'waitfor'}
    # Linear comment scanning: repeated unclosed /* must not cause regex backtracking.
    output, cursor = [], 0
    while True:
        start = value.find('/*', cursor)
        if start < 0:
            output.append(value[cursor:])
            break
        end = value.find('*/', start + 2)
        if end < 0:
            output.append(value[cursor:])
            break
        output.append(value[cursor:start])
        left = re.search(r'[a-z]{1,12}$', value[max(cursor, start-12):start])
        right = re.match(r'[a-z]{1,12}', value[end+2:end+14])
        output.append('' if left and right and left[0]+right[0] in keywords else ' ')
        cursor = end + 2
    variants = [''.join(output)]
    for text in variants:
        text = re.sub(r'--[^\r\n]*[\r\n]+', ' ', text)
        words = ' '.join(re.findall(r'[a-z_]+|\d+|[^\w\s]', text))
        if re.search(r'\bunion\s+(?:all\s+|distinct\s+)?select\b|\bselect\s+(?:\*|\w+(?:\s*,\s*\w+)*)\s+from\s+\w+', words):
            return True
        if re.search(r'\b(?:or|and)\s+[\s\x27\x22]*(?:\d+|[a-z_]+)[\s\x27\x22]*(?:=|<>|!=|\blike\b)\s*[\s\x27\x22]*(?:\d+|[a-z_]+)', text):
            return True
        if re.search(r'\b(?:pg_sleep|sleep|benchmark)\s*\(\s*\d|\bwaitfor\s+delay\b|\b(?:extractvalue|updatexml)\s*\(', text):
            return True
        if re.search(r'\b(?:or|and)\s+(?:true\b|exists\s*\(\s*select\b)|\b(?:randomblob|zeroblob)\s*\(\s*\d{6,}', text):
            return True
        if re.search(r';\s*(?:drop|alter|insert|delete|update|exec(?:ute)?|select)\b', text):
            return True
        if re.search(r'\b(?:load_file|into\s+(?:out|dump)file|information_schema)\b', text):
            return True
    return False


class _HTMLInspection(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.dangerous = False

    def handle_starttag(self, tag, attrs):
        if tag in {'script', 'iframe', 'object', 'embed', 'base', 'animate', 'set', 'foreignobject'}:
            self.dangerous = True
        for name, value in attrs:
            if name.startswith('on') and len(name) > 2 or name == 'srcdoc':
                self.dangerous = True
            if value and name in {'href', 'src', 'action', 'formaction', 'xlink:href', 'data'} and _unsafe_scheme(value):
                self.dangerous = True

    handle_startendtag = handle_starttag


def _unsafe_scheme(value):
    compact = re.sub(r'[\s\x00-\x20\x7f]+', '', value)
    return compact.startswith(('javascript:', 'vbscript:', 'data:text/html', 'data:image/svg+xml'))


def _xss(value):
    parser = _HTMLInspection()
    parser.feed(value)
    return (parser.dangerous or _unsafe_scheme(value.strip()) or
            bool(re.search(r'<\s*(?:script|iframe|object|embed)\b|\bon[a-z]+\s*=\s*[\x22\x27]?(?:alert|confirm|prompt|fetch|eval)\s*\(', value)))


def _traversal(value):
    path = value.replace('\\', '/')
    return bool(re.search(r'(?:^|[/\s=])\.\.(?:/|$)|(?:^|[/\s=])(?:etc/(?:passwd|shadow)|proc/self|windows/(?:win.ini|system32))\b|\b[a-z]:/', path)
                or re.search(r'(?:^|/)(?:\.env(?:\.[\w-]+)?|\.git|id_rsa|wp-config\.php)(?:$|[/\s?])', path))


def _command(value):
    # Require shell structure AND an executable token, not ordinary punctuation.
    commands = r'(?:cat|curl|wget|bash|sh|cmd(?:\.exe)?|powershell|whoami|id|nc|netcat|python\d*|perl|rm|ping)\b'
    return bool(re.search(r'(?:\$\(|`|(?:;|&&|\|\||\|)\s*)\s*' + commands, value))


DETECTORS = {'sql_injection': _sql, 'xss': _xss, 'path_traversal': _traversal, 'command_injection': _command}


def inspect_values(values: list[str], enabled_categories: set[str] | None = None) -> tuple[list[str], int]:
    matched = set()
    for value in values:
        for offset in range(0, max(1, len(value)), 32512):
            normalized = normalize_for_detection(value[offset:offset + 32768])
            for rule in RULES:
                if rule.rule_id not in matched and (enabled_categories is None or rule.category in enabled_categories):
                    if DETECTORS[rule.category](normalized):
                        matched.add(rule.rule_id)
    rules = [rule for rule in RULES if rule.rule_id in matched]
    return [rule.rule_id for rule in rules], sum(rule.score for rule in rules)


def inspect_headers(headers) -> bool:
    names = [name.lower() for name, _ in headers.items()]
    return (any(name in names for name in ('x-http-method-override', 'x-method-override', 'x-http-method')) or
            any(any(ord(char) < 32 and char != '\t' or ord(char) == 127 for char in value)
                for _, value in headers.items()))
