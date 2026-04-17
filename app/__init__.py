from flask import Flask
from app.metrics import setup_metrics
from app.routes import register_routes
from app.middleware import analyze_request


def create_app():
    app = Flask(__name__, template_folder='../templates', static_folder='../static')
    app.secret_key = 'ids-secret-key-2024'

    # Register IDS middleware — runs before EVERY request
    app.before_request(analyze_request)

    # Set up Prometheus metrics endpoint
    setup_metrics(app)

    # Register all routes
    register_routes(app)

    return app
