def compute_risk_score(ml_score, rule_flag, freq_score):
    """
    Combine ML anomaly score + rule flag + frequency into a single risk score.

    Weights:
      ML score   → 50%  (detects zero-days and anomalies)
      Rule flag  → 35%  (detects known attack signatures)
      Freq score → 15%  (detects DDoS / brute-force)

    Returns: (risk_score: float, decision: str)
      decision ∈ {'ALLOW', 'ALERT', 'BLOCK'}
    """
    risk_score = (ml_score * 0.50) + (rule_flag * 0.35) + (freq_score * 0.15)
    risk_score = min(max(risk_score, 0.0), 1.0)   # clamp to [0, 1]

    # Any confirmed rule hit → escalate immediately
    if rule_flag == 1 and risk_score >= 0.35:
        return round(risk_score, 4), 'BLOCK'

    if risk_score < 0.42:
        decision = 'ALLOW'
    elif risk_score < 0.70:
        decision = 'ALERT'
    else:
        decision = 'BLOCK'

    return round(risk_score, 4), decision
