from flask import Flask, render_template, request, jsonify
import re
import random

app = Flask(__name__, 
            template_folder='app/templates',
            static_folder='app/static')

class SimplePhishingDetector:
    def __init__(self):
        # Common phishing keywords to look for
        self.suspicious_keywords = [
            'urgent', 'verify', 'account', 'suspended', 'update', 'confirm',
            'security', 'bank', 'payment', 'click', 'link', 'password',
            'credential', 'login', 'access', 'limited', 'offer', 'prize',
            'won', 'winner', 'lottery', 'official', 'alert', 'attention'
        ]
        
        # URL patterns that might be suspicious
        self.suspicious_url_patterns = [
            r'bit\.ly', r'tinyurl\.com', r'goo\.gl', r't\.co',
            r'ip address', r'paypal.*\.com', r'apple.*\.com', r'microsoft.*\.com',
            r'amazon.*\.com', r'google.*\.com', r'facebook.*\.com'
        ]
    
    def analyze_email(self, content, sender='', subject=''):
        """
        Analyze email content for phishing risk
        
        Args:
            content (str): Raw email content
            sender (str, optional): Email sender
            subject (str, optional): Email subject
            
        Returns:
            dict: Analysis results with risk score and details
        """
        # Process the email content
        processed_email = self._process_email(content, sender, subject)
        
        # Analyze content
        content_analysis = self._analyze_content(processed_email)
        
        # Analyze sender
        sender_analysis = self._analyze_sender(processed_email)
        
        # Analyze URLs
        url_analysis = self._analyze_urls(processed_email)
        
        # Calculate overall risk score (weighted average)
        weights = {
            'content_score': 0.5,  # Weight for content analysis
            'sender_score': 0.3,   # Weight for sender analysis
            'url_score': 0.2       # Weight for URL analysis
        }
        
        risk_score = (
            weights['content_score'] * content_analysis['score'] +
            weights['sender_score'] * sender_analysis['score'] +
            weights['url_score'] * url_analysis['score']
        )
        
        # Determine risk level
        if risk_score < 0.3:
            risk_level = 'Low'
        elif risk_score < 0.7:
            risk_level = 'Medium'
        else:
            risk_level = 'High'
        
        # Format the results
        return {
            'risk_score': round(risk_score * 100),  # Convert to percentage
            'risk_level': risk_level,
            'analysis_details': {
                'content_analysis': content_analysis,
                'sender_analysis': sender_analysis,
                'url_analysis': url_analysis
            }
        }
    
    def _process_email(self, content, sender='', subject=''):
        """Process email content and extract relevant information"""
        # Extract URLs
        urls = re.findall(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+', content)
        processed_urls = []
        
        for url in urls:
            processed_urls.append({
                'url': url,
                'domain': url.split('/')[2] if len(url.split('/')) > 2 else url
            })
        
        # Identify suspicious keywords
        text_lower = content.lower()
        suspicious_words = [keyword for keyword in self.suspicious_keywords if keyword in text_lower]
        
        return {
            'sender': sender,
            'subject': subject,
            'body': content,
            'urls': processed_urls,
            'suspicious_keywords': suspicious_words
        }
    
    def _analyze_content(self, processed_email):
        """Analyze email content for phishing indicators"""
        body = processed_email.get('body', '')
        subject = processed_email.get('subject', '')
        suspicious_keywords = processed_email.get('suspicious_keywords', [])
        
        # Initialize flags and score
        flags = []
        score = 0.0
        
        # Check for suspicious keywords
        if suspicious_keywords:
            keyword_ratio = len(suspicious_keywords) / 24  # Normalize by total keywords
            score += min(0.5, keyword_ratio)  # Cap at 0.5
            if len(suspicious_keywords) >= 3:
                flags.append(f"Contains multiple suspicious keywords: {', '.join(suspicious_keywords[:5])}")
        
        # Check for urgent language
        urgent_patterns = [
            r'urgent', r'immediate', r'attention required', r'act now',
            r'limited time', r'expires', r'deadline', r'asap'
        ]
        
        combined_text = (subject + ' ' + body).lower()
        urgent_count = sum(1 for pattern in urgent_patterns if re.search(pattern, combined_text))
        
        if urgent_count > 0:
            urgent_score = min(0.3, urgent_count * 0.1)  # Cap at 0.3
            score += urgent_score
            flags.append("Uses urgent or time-sensitive language")
        
        # Add a small random factor to make it more realistic
        score += random.uniform(-0.05, 0.05)
        
        # Ensure score is between 0 and 1
        score = max(0.0, min(1.0, score))
        
        return {
            'score': score,
            'flags': flags
        }
    
    def _analyze_sender(self, processed_email):
        """Analyze sender information for phishing indicators"""
        sender = processed_email.get('sender', '')
        
        # Initialize flags and score
        flags = []
        score = 0.0
        
        # Simple check for suspicious sender domains
        if sender:
            suspicious_domains = ['tempmail.com', 'fakeemail.com', 'mailinator.com']
            if any(domain in sender.lower() for domain in suspicious_domains):
                score += 0.6
                flags.append("Sender domain has poor reputation")
            
            # Check if sender uses free email provider
            free_providers = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com']
            if any(provider in sender.lower() for provider in free_providers):
                score += 0.3
                flags.append("Sender uses a free email provider")
        
        # Add a small random factor
        score += random.uniform(-0.05, 0.05)
        
        # Ensure score is between 0 and 1
        score = max(0.0, min(1.0, score))
        
        return {
            'score': score,
            'flags': flags
        }
    
    def _analyze_urls(self, processed_email):
        """Analyze URLs in email for phishing indicators"""
        urls = processed_email.get('urls', [])
        
        # Initialize flags and score
        flags = []
        score = 0.0
        
        if not urls:
            return {'score': 0.0, 'flags': []}
        
        # Check number of URLs
        if len(urls) > 5:
            score += 0.2
            flags.append(f"Contains multiple URLs ({len(urls)})")
        
        # Analyze each URL
        suspicious_url_count = 0
        for url_info in urls:
            url = url_info.get('url', '')
            domain = url_info.get('domain', '')
            
            # Check for suspicious URL patterns
            for pattern in self.suspicious_url_patterns:
                if re.search(pattern, url.lower()):
                    suspicious_url_count += 1
                    flags.append(f"URL contains suspicious pattern: {url}")
                    break
        
        # Calculate score based on suspicious URLs
        if suspicious_url_count > 0:
            url_ratio = suspicious_url_count / len(urls)
            score += min(0.8, url_ratio)  # Cap at 0.8
        
        # Add a small random factor
        score += random.uniform(-0.05, 0.05)
        
        # Ensure score is between 0 and 1
        score = max(0.0, min(1.0, score))
        
        return {
            'score': score,
            'flags': flags
        }

# Create detector instance
detector = SimplePhishingDetector()

@app.route('/')
def index():
    """Render the main page"""
    return render_template('index.html')

@app.route('/api/analyze-email', methods=['POST'])
def analyze_email():
    """
    Analyze email content for phishing risk
    """
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400
    
    data = request.get_json()
    
    # Validate input
    if 'email_content' not in data or not data['email_content'].strip():
        return jsonify({"error": "Email content is required"}), 400
    
    try:
        # Analyze the email
        analysis_result = detector.analyze_email(
            content=data['email_content'],
            sender=data.get('sender_email', ''),
            subject=data.get('subject', '')
        )
        
        return jsonify(analysis_result), 200
    
    except Exception as e:
        print(f"Error analyzing email: {str(e)}")
        return jsonify({"error": f"Analysis failed: {str(e)}"}), 500

@app.route('/api/health')
def health_check():
    """Health check endpoint"""
    return {'status': 'healthy'}, 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
