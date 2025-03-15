from flask import Flask
from flask_cors import CORS

def create_app(config=None):
    app = Flask(__name__)
    CORS(app)
    
    # Load configuration
    if config:
        app.config.from_object(config)
    else:
        app.config.from_mapping(
            SECRET_KEY='dev',
            MODEL_PATH='app/models/phishing_model',
        )
    
    # Register blueprints
    from app.routes import main_bp, api_bp
    app.register_blueprint(main_bp)
    app.register_blueprint(api_bp, url_prefix='/api')
    
    # Create health check endpoint
    @app.route('/api/health')
    def health_check():
        return {'status': 'healthy'}, 200
    
    return app
