import time
import random
from flask import jsonify, render_template, request
from app.middleware import get_stats, blocked_ips, alert_log, rate_tracker, analyze_payload


def register_routes(app):

    @app.route('/')
    def index():
        return render_template('index.html')

    @app.route('/dashboard')
    def dashboard():
        return render_template('dashboard.html')

    @app.route('/api/stats')
    def api_stats():
        return jsonify(get_stats())

    @app.route('/api/test/normal')
    def test_normal():
        result = analyze_payload('normal GET /home user=john_doe page=home', request.remote_addr)
        return jsonify({'status': 'ok', 'decision': result['decision'], 'risk': result['risk_score']})

    @app.route('/api/test/sqli')
    def test_sqli():
        payload = "SELECT * FROM users WHERE id=1 UNION SELECT username,password FROM admin-- ' OR 1=1"
        result = analyze_payload(payload, request.remote_addr)
        status = 403 if result['decision'] == 'BLOCK' else 200
        return jsonify({'decision': result['decision'], 'risk': result['risk_score']}), status

    @app.route('/api/test/xss')
    def test_xss():
        payload = "<script>alert('XSS')</script> javascript:eval(document.cookie) onerror=alert(1)"
        result = analyze_payload(payload, request.remote_addr)
        status = 403 if result['decision'] == 'BLOCK' else 200
        return jsonify({'decision': result['decision'], 'risk': result['risk_score']}), status

    @app.route('/api/test/ddos')
    def test_ddos():
        payload = "flood ddos stress hammer benchmark(10000000,1)"
        result = analyze_payload(payload, request.remote_addr)
        status = 403 if result['decision'] == 'BLOCK' else 200
        return jsonify({'decision': result['decision'], 'risk': result['risk_score']}), status

    @app.route('/api/test/traversal')
    def test_traversal():
        payload = "../../etc/passwd %2e%2e%2fetc/shadow ..\\..\\windows\\system32"
        result = analyze_payload(payload, request.remote_addr)
        status = 403 if result['decision'] == 'BLOCK' else 200
        return jsonify({'decision': result['decision'], 'risk': result['risk_score']}), status

    @app.route('/api/reset-ip', methods=['POST'])
    def reset_ip():
        ip = request.json.get('ip', '')
        if ip in blocked_ips:
            blocked_ips.discard(ip)
            return jsonify({'status': 'unblocked', 'ip': ip})
        return jsonify({'status': 'not_found', 'ip': ip})

    @app.route('/api/reset-rates', methods=['POST'])
    def reset_rates():
        rate_tracker.clear()
        blocked_ips.clear()
        alert_log.clear()
        return jsonify({'status': 'reset', 'message': 'All counters and blocks cleared'})

    @app.route('/health')
    def health():
        return jsonify({'status': 'healthy', 'ids': 'active'})

    @app.errorhandler(403)
    def forbidden(e):
        return render_template('blocked.html'), 403

    @app.errorhandler(404)
    def not_found(e):
        return jsonify({'error': 'Not found'}), 404
