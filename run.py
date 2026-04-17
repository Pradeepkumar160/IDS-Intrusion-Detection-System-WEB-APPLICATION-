"""
IDS — Real-Time Web Application Intrusion Detection System
Run with: python run.py
"""
import os
import sys

# Ensure project root is in path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import create_app

if __name__ == '__main__':
    app = create_app()
    print()
    print("=" * 55)
    print("  ⚡  IDS — Intrusion Detection System")
    print("  Hybrid ML + Rule-Based | Python + Flask")
    print("=" * 55)
    print("  Dashboard  →  http://127.0.0.1:5000/dashboard")
    print("  Metrics    →  http://127.0.0.1:5000/metrics")
    print("  Health     →  http://127.0.0.1:5000/health")
    print("=" * 55)
    print()
    app.run(host='0.0.0.0', port=5000, debug=False)
