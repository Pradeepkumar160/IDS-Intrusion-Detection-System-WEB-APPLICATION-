import re
import math
from collections import Counter


def get_features(request_str, ip, rate_tracker):
    """
    Extract 5 numeric features from an HTTP request string.
    Returns a list: [length, specials, kw_score, freq, entropy]
    """
    # 1. Request length
    length = len(request_str)

    # 2. Special character count (common in SQL injection / XSS)
    specials = len(re.findall(r"['\";\\<>()\[\]{}]", request_str))

    # 3. Keyword score - SQL / script keywords
    keywords = [
        'select', 'union', 'insert', 'update', 'delete', 'drop',
        'exec', 'execute', 'script', 'alert', 'onerror', 'onload',
        'javascript', 'eval', 'cast(', 'char(', 'concat(', 'sleep('
    ]
    lower_req = request_str.lower()
    kw_score = sum(1 for k in keywords if k in lower_req)

    # 4. Request frequency per IP (requests per window)
    freq = rate_tracker.get(ip, 0)

    # 5. Shannon entropy of the request string
    if len(request_str) > 0:
        counts = Counter(request_str)
        total = len(request_str)
        entropy = -sum(
            (c / total) * math.log2(c / total)
            for c in counts.values() if c > 0
        )
    else:
        entropy = 0.0

    return [length, specials, kw_score, freq, entropy]
