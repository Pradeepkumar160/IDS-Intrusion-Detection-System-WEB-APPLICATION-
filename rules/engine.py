import re

# SQL Injection patterns
SQLI_PATTERNS = [
    r"(\bunion\b.*\bselect\b)",
    r"(\bselect\b.*\bfrom\b)",
    r"(\binsert\b.*\binto\b)",
    r"(\bdrop\b.*\btable\b)",
    r"(\bexec\b|\bexecute\b)\s*\(",
    r"(--|#|/\*)\s*$",
    r"'\s*(or|and)\s*'?\d",
    r"\bsleep\s*\(\d+\)",
    r"\bwaitfor\b.*\bdelay\b",
    r"(char|cast|convert)\s*\(",
    r"1\s*=\s*1",
    r"'\s*;\s*--",
]

# Cross-Site Scripting (XSS) patterns
XSS_PATTERNS = [
    r"<\s*script[^>]*>",
    r"javascript\s*:",
    r"on(error|load|click|mouseover|focus)\s*=",
    r"<\s*iframe",
    r"<\s*img[^>]+src\s*=\s*['\"]?\s*javascript",
    r"eval\s*\(",
    r"document\s*\.\s*cookie",
    r"document\s*\.\s*write\s*\(",
    r"window\s*\.\s*location",
    r"alert\s*\(",
]

# DDoS / Flood patterns
DDOS_PATTERNS = [
    r"(flood|stress|hammer|ddos|dos\b)",
    r"(benchmark|sleep)\s*\(\s*\d{4,}",  # long sleep = DoS
]

# Path Traversal
TRAVERSAL_PATTERNS = [
    r"\.\./",
    r"\.\.\\",
    r"%2e%2e%2f",
    r"%252e%252e",
]

ALL_PATTERNS = {
    'sqli':      SQLI_PATTERNS,
    'xss':       XSS_PATTERNS,
    'ddos':      DDOS_PATTERNS,
    'traversal': TRAVERSAL_PATTERNS,
}


def check_rules(payload):
    """
    Check payload against all rule sets.
    Returns: (flag: int, attack_type: str)
      flag=1 means attack detected, flag=0 means clean
    """
    payload_lower = payload.lower()
    for attack_type, patterns in ALL_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, payload_lower):
                return 1, attack_type
    return 0, 'none'
