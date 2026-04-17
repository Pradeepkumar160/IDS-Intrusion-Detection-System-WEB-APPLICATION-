import time
import joblib
import numpy as np
import os
import sys

from flask import request, abort, g

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ml.features import get_features
from rules.engine import check_rules
from app.risk_engine import compute_risk_score
from app import metrics as m

# ── Load ML model ──────────────────────────────────────────────────────────────
MODEL_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'ml', 'model.pkl')

if not os.path.exists(MODEL_PATH):
    print("[!] model.pkl not found — training now...")
    from ml.train import train_model
    train_model(MODEL_PATH)

model = joblib.load(MODEL_PATH)
print(f"[+] IDS model loaded from {MODEL_PATH}")

# ── In-memory state ────────────────────────────────────────────────────────────
rate_tracker  = {}    # ip → request count in current window
blocked_ips   = set() # permanently blocked IPs
alert_log     = []    # list of alert dicts (last 500)
MAX_LOG       = 500
RATE_LIMIT    = 60    # requests before freq score hits 1.0


def analyze_request():
    """
    Main IDS hook — runs before every Flask request.
    Skips the /metrics, /dashboard, /static routes.
    """
    # Skip internal/dashboard routes
    if request.path.startswith(('/metrics', '/static', '/favicon', '/dashboard', '/api/stats', '/api/reset', '/health')):
        return

    ip = request.remote_addr or '0.0.0.0'
    start = time.time()

    # ── Check if IP is already blocked ────────────────────────────────────────
    if ip in blocked_ips:
        _log_event(ip, 'BLOCK', 1.0, 1, 'previously_blocked', request.path)
        abort(403)

    # ── Rate tracking ──────────────────────────────────────────────────────────
    rate_tracker[ip] = rate_tracker.get(ip, 0) + 1
    freq_score = min(rate_tracker[ip] / RATE_LIMIT, 1.0)

    # ── Build payload string ───────────────────────────────────────────────────
    payload_parts = [
        request.url,
        str(request.args.to_dict()),
        request.get_data(as_text=True),
        str(dict(request.headers)),
    ]
    payload = ' '.join(payload_parts)

    # ── Feature extraction ─────────────────────────────────────────────────────
    features = get_features(payload, ip, rate_tracker)
    features_arr = np.array(features).reshape(1, -1)

    # ── ML score ───────────────────────────────────────────────────────────────
    # score_samples returns negative: more negative = more anomalous
    raw_score = model.score_samples(features_arr)[0]
    # Normalize: Isolation Forest score_samples returns ~[-0.5, 0.5]
    # More negative = more anomalous. Map to [0,1].
    ml_score = float(np.clip((-raw_score - 0.05) / 0.5, 0.0, 1.0))

    # ── Rule check ─────────────────────────────────────────────────────────────
    rule_flag, attack_type = check_rules(payload)

    # ── Risk scoring ───────────────────────────────────────────────────────────
    risk_score, decision = compute_risk_score(ml_score, rule_flag, freq_score)

    # ── Record latency ─────────────────────────────────────────────────────────
    latency = time.time() - start
    m.ids_latency.observe(latency)
    m.ids_requests_total.inc()

    # Store for response headers (optional debug)
    g.ids_decision   = decision
    g.ids_risk_score = risk_score
    g.ids_attack     = attack_type

    # ── Update attack-type counters ────────────────────────────────────────────
    if rule_flag:
        _inc_attack_counter(attack_type)

    # ── Take action ───────────────────────────────────────────────────────────
    if decision == 'BLOCK':
        blocked_ips.add(ip)
        m.ids_blocked_ips.set(len(blocked_ips))
        m.ids_blocked_total.inc()
        _log_event(ip, 'BLOCK', risk_score, rule_flag, attack_type, request.path)
        abort(403)

    elif decision == 'ALERT':
        m.ids_alerts_total.inc()
        _log_event(ip, 'ALERT', risk_score, rule_flag, attack_type, request.path)

    else:
        m.ids_allowed_total.inc()


def _inc_attack_counter(attack_type):
    counters = {
        'sqli':      m.ids_sqli_total,
        'xss':       m.ids_xss_total,
        'ddos':      m.ids_ddos_total,
        'traversal': m.ids_traversal_total,
    }
    c = counters.get(attack_type)
    if c:
        c.inc()


def _log_event(ip, decision, risk_score, rule_flag, attack_type, path):
    event = {
        'time':        time.strftime('%H:%M:%S'),
        'ip':          ip,
        'decision':    decision,
        'risk_score':  risk_score,
        'attack_type': attack_type,
        'path':        path,
        'rule_flag':   rule_flag,
    }
    alert_log.append(event)
    if len(alert_log) > MAX_LOG:
        alert_log.pop(0)


def get_stats():
    """Return current IDS statistics for the dashboard."""
    total   = int(m.ids_requests_total._value.get())
    blocked = int(m.ids_blocked_total._value.get())
    alerts  = int(m.ids_alerts_total._value.get())
    allowed = int(m.ids_allowed_total._value.get())

    return {
        'total_requests':  total,
        'blocked':         blocked,
        'alerts':          alerts,
        'allowed':         allowed,
        'blocked_ips':     list(blocked_ips),
        'blocked_ips_count': len(blocked_ips),
        'sqli_count':      int(m.ids_sqli_total._value.get()),
        'xss_count':       int(m.ids_xss_total._value.get()),
        'ddos_count':      int(m.ids_ddos_total._value.get()),
        'traversal_count': int(m.ids_traversal_total._value.get()),
        'recent_events':   list(reversed(alert_log[-20:])),
    }


def analyze_payload(payload, ip):
    """
    Directly analyze a payload string through the full IDS pipeline.
    Used by demo routes to simulate attacks properly.
    Returns dict with decision and risk_score, and logs the event.
    """
    import time as _time
    import numpy as _np

    start = _time.time()

    # Rate tracking
    rate_tracker[ip] = rate_tracker.get(ip, 0) + 1
    freq_score = min(rate_tracker[ip] / RATE_LIMIT, 1.0)

    # Feature extraction
    features = get_features(payload, ip, rate_tracker)
    features_arr = _np.array(features).reshape(1, -1)

    # ML score
    raw_score = model.score_samples(features_arr)[0]
    ml_score = float(_np.clip((-raw_score - 0.05) / 0.5, 0.0, 1.0))

    # Rule check
    rule_flag, attack_type = check_rules(payload)

    # Risk score
    risk_score, decision = compute_risk_score(ml_score, rule_flag, freq_score)

    # Metrics
    latency = _time.time() - start
    m.ids_latency.observe(latency)
    m.ids_requests_total.inc()

    if rule_flag:
        _inc_attack_counter(attack_type)

    if decision == 'BLOCK':
        blocked_ips.add(ip)
        m.ids_blocked_ips.set(len(blocked_ips))
        m.ids_blocked_total.inc()
        _log_event(ip, 'BLOCK', risk_score, rule_flag, attack_type, '/api/test/' + attack_type)
    elif decision == 'ALERT':
        m.ids_alerts_total.inc()
        _log_event(ip, 'ALERT', risk_score, rule_flag, attack_type, '/api/test/' + attack_type)
    else:
        m.ids_allowed_total.inc()
        _log_event(ip, 'ALLOW', risk_score, rule_flag, attack_type, '/api/test/normal')

    return {'decision': decision, 'risk_score': risk_score, 'attack_type': attack_type}
