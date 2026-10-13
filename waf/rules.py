import re
from dataclasses import dataclass
from urllib.parse import unquote_plus


@dataclass(frozen=True)
class DetectionRule:
    rule_id: str
    category: str
    score: int
    pattern: re.Pattern
    description: str


RULES = [
    DetectionRule(
        "SQLI-001",
        "sql_injection",
        6,
        re.compile(
            r"(?is)(\bunion\b\s+\bselect\b|\bselect\b.+\bfrom\b|\bor\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+|--|/\*.*?\*/|;\s*(drop|alter|insert|delete|update)\b)"
        ),
        "Common SQL injection keywords and boolean/comment operators.",
    ),
    DetectionRule(
        "XSS-001",
        "xss",
        6,
        re.compile(
            r"(?is)(<\s*script\b|javascript\s*:|on(?:error|load|click|mouseover)\s*=|<\s*img\b[^>]+onerror\s*=|<\s*svg\b[^>]*onload\s*=)"
        ),
        "Common script tags, event handlers, and javascript URLs.",
    ),
    DetectionRule(
        "TRAV-001",
        "path_traversal",
        6,
        re.compile(
            r"(?is)(\.\.[/\\]|%2e%2e|%252e%252e|/(?:etc/passwd|proc/self|windows/win\.ini)|[a-z]:\\)"
        ),
        "Directory traversal and sensitive local file path markers.",
    ),
]


def normalize_for_detection(value: str) -> str:
    normalized = value
    for _ in range(3):
        decoded = unquote_plus(normalized)
        if decoded == normalized:
            break
        normalized = decoded
    return normalized.lower()


def inspect_values(values: list[str]) -> tuple[list[str], int]:
    matched: list[str] = []
    score = 0
    for value in values:
        normalized = normalize_for_detection(value)
        for rule in RULES:
            if rule.pattern.search(normalized):
                if rule.rule_id not in matched:
                    matched.append(rule.rule_id)
                    score += rule.score
    return matched, score
