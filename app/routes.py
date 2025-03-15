from flask import Blueprint, render_template, request, jsonify, current_app
import os
import json
from app.utils.email_processor import EmailProcessor
from app.utils.risk_analyzer import RiskAnalyzer

# Create blueprints
main_bp = Blueprint('main', __name__)
api_bp = Blueprint('api', __name__)

# Initialize processors
email_processor = EmailProcessor()
risk_analyzer = RiskAnalyzer()

# Web routes
@main_bp.route('/')
def index():
    """Render the main page"""
    return render_template('index.html')

# API routes
@api_bp.route('/analyze-email', methods=['POST'])
def analyze_email():
    """
    Analyze email content for phishing risk
    
    Expected JSON payload:
    {
        "email_content": "Full email text or content",
        "sender_email": "Optional sender email",
        "subject": "Optional subject"
    }
    """
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400
    
    data = request.get_json()
    
    # Validate input
    if 'email_content' not in data or not data['email_content'].strip():
        return jsonify({"error": "Email content is required"}), 400
    
    try:
        # Process the email
        processed_email = email_processor.process(
            content=data['email_content'],
            sender=data.get('sender_email', ''),
            subject=data.get('subject', '')
        )
        
        # Analyze the processed email
        analysis_result = risk_analyzer.analyze(processed_email)
        
        return jsonify(analysis_result), 200
    
    except Exception as e:
        current_app.logger.error(f"Error analyzing email: {str(e)}")
        return jsonify({"error": f"Analysis failed: {str(e)}"}), 500
