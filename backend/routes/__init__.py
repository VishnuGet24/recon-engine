"""Route blueprints."""

from routes.admin_routes import bp as admin_bp
from routes.auth_routes import bp as auth_bp
from routes.auth_routes import public_bp as auth_public_bp
from routes.api_routes import bp as api_bp
from routes.dashboard_routes import bp as dashboard_bp
from routes.scan_routes import bp as scan_bp
from routes.scan_routes import public_bp as scan_public_bp


def register_blueprints(app):
    app.register_blueprint(api_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(auth_public_bp)
    app.register_blueprint(scan_bp)
    app.register_blueprint(scan_public_bp)
    app.register_blueprint(admin_bp)
