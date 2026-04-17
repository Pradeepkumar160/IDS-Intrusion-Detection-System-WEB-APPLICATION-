"""
Simple in-memory metrics — no prometheus_client required.
Exposes a /metrics endpoint in Prometheus text format manually.
"""
from flask import Response
from threading import Lock

_lock = Lock()

_counters = {
    'ids_requests_total':    0,
    'ids_blocked_total':     0,
    'ids_alerts_total':      0,
    'ids_allowed_total':     0,
    'ids_sqli_total':        0,
    'ids_xss_total':         0,
    'ids_ddos_total':        0,
    'ids_traversal_total':   0,
    'ids_blocked_ips_total': 0,
}

_latencies = []


class _Counter:
    def __init__(self, name):
        self.name = name

    def inc(self, amount=1):
        with _lock:
            _counters[self.name] += amount

    class _Val:
        def __init__(self, name): self.name = name
        def get(self): return _counters[self.name]

    @property
    def _value(self):
        return self._Val(self.name)


class _Gauge(_Counter):
    def set(self, value):
        with _lock:
            _counters[self.name] = value


class _Histogram:
    def observe(self, value):
        with _lock:
            _latencies.append(value)
            if len(_latencies) > 1000:
                _latencies.pop(0)

    def avg(self):
        if not _latencies:
            return 0.0
        return sum(_latencies) / len(_latencies)


# Public instances used in middleware.py
ids_requests_total   = _Counter('ids_requests_total')
ids_blocked_total    = _Counter('ids_blocked_total')
ids_alerts_total     = _Counter('ids_alerts_total')
ids_allowed_total    = _Counter('ids_allowed_total')
ids_sqli_total       = _Counter('ids_sqli_total')
ids_xss_total        = _Counter('ids_xss_total')
ids_ddos_total       = _Counter('ids_ddos_total')
ids_traversal_total  = _Counter('ids_traversal_total')
ids_blocked_ips      = _Gauge('ids_blocked_ips_total')
ids_latency          = _Histogram()


def _prom_text():
    lines = []
    for name, val in _counters.items():
        lines.append(f'# HELP {name} IDS metric')
        lines.append(f'# TYPE {name} counter')
        lines.append(f'{name} {val}')
    avg_lat = ids_latency.avg()
    lines.append('# HELP ids_latency_avg_seconds Average IDS latency')
    lines.append('# TYPE ids_latency_avg_seconds gauge')
    lines.append(f'ids_latency_avg_seconds {avg_lat:.6f}')
    return '\n'.join(lines) + '\n'


def setup_metrics(app):
    @app.route('/metrics')
    def metrics():
        return Response(_prom_text(), mimetype='text/plain')
