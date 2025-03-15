import re
import requests
from urllib.parse import urlparse
from app.models.model_loader import get_model

class RiskAnalyzer:
    """
    Class for analyzing emails and calculating phishing risk scores
    """
    
    def __init__(self):
        # Load the NLP model
        self.model = get_model()
        
        # Risk weights for different components
        self.weights = {
            'content_score': 0.5,  # Weight for content analysis
            'sender_score': 0.3,   # Weight for sender analysis
            'url_score': 0.2       # Weight for URL analysis
        }
        
        # Risk level thresholds
        self.risk_levels = {
            'low': 0.3,      # Below 30% is low risk
            'medium': 0.7    # Below 70% is medium risk, above is high risk
        }
    
    def analyze(self, processed_email):
        """
        Analyze processed email and calculate risk score
        
        Args:
            processed_email (dict): Processed email information
            
        Returns:
            dict: Analysis results with risk score and details
        """
        # Analyze content
        content_analysis = self._analyze_content(processed_email)
        
        # Analyze sender
        sender_analysis = self._analyze_sender(processed_email)
        
        # Analyze URLs
        url_analysis = self._analyze_urls(processed_email)
        
        # Calculate overall risk score (weighted average)
        risk_score = (
            self.weights['content_score'] * content_analysis['score'] +
            self.weights['sender_score'] * sender_analysis['score'] +
            self.weights['url_score'] * url_analysis['score']
        )
        
        # Determine risk level
        if risk_score < self.risk_levels['low']:
            risk_level = 'Low'
        elif risk_score < self.risk_levels['medium']:
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
        
        # Check for threatening language
        threat_patterns = [
            r'suspend', r'terminate', r'block', r'restrict', r'limit',
            r'close', r'disable', r'unauthorized', r'fraud', r'illegal'
        ]
        
        threat_count = sum(1 for pattern in threat_patterns if re.search(pattern, combined_text))
        
        if threat_count > 0:
            threat_score = min(0.3, threat_count * 0.1)  # Cap at 0.3
            score += threat_score
            flags.append("Contains threatening language")
        
        # Check for personal/financial information requests
        info_patterns = [
            r'password', r'credit card', r'account number', r'social security',
            r'ssn', r'credentials', r'login', r'verify.*account', r'confirm.*details'
        ]
        
        info_count = sum(1 for pattern in info_patterns if re.search(pattern, combined_text))
        
        if info_count > 0:
            info_score = min(0.4, info_count * 0.1)  # Cap at 0.4
            score += info_score
            flags.append("Requests personal or financial information")
        
        # Check for poor grammar/spelling (simplified check)
        grammar_issues = self._check_grammar_issues(body)
        if grammar_issues:
            score += 0.2
            flags.append("Contains grammar or spelling issues")
        
        # Use NLP model for additional content analysis
        if self.model and body:
            try:
                model_score = self.model.predict_phishing_probability(body)
                # Blend model score with heuristic score
                score = 0.7 * model_score + 0.3 * score
            except Exception:
                # If model fails, continue with heuristic score
                pass
        
        # Cap score at 1.0
        score = min(1.0, score)
        
        return {
            'score': score,
            'flags': flags
        }
    
    def _analyze_sender(self, processed_email):
        """Analyze sender information for phishing indicators"""
        sender_info = processed_email.get('sender_info', {})
        
        # Initialize flags and score
        flags = []
        score = 0.0
        
        # Check if sender email is valid
        if not sender_info.get('valid', False):
            score += 0.7
            flags.append(f"Invalid sender email: {sender_info.get('reason', 'Unknown reason')}")
            return {'score': score, 'flags': flags}
        
        # Check if sender domain is an IP address
        if sender_info.get('is_ip_address', False):
            score += 0.8
            flags.append("Sender domain is an IP address")
        
        # Check if sender uses free email provider
        if sender_info.get('is_free_provider', False):
            score += 0.3
            flags.append("Sender uses a free email provider")
        
        # Check for domain age and reputation (simplified)
        # In a production system, this would connect to external reputation services
        domain = sender_info.get('domain')
        if domain:
            # Placeholder for domain reputation check
            # In a real system, this would query external APIs
            suspicious_domains = ['tempmail.com', 'fakeemail.com', 'mailinator.com']
            if any(d in domain for d in suspicious_domains):
                score += 0.6
                flags.append("Sender domain has poor reputation")
        
        # Cap score at 1.0
        score = min(1.0, score)
        
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
            
            # Check for IP addresses in URL
            if url_info.get('is_ip_address', False):
                suspicious_url_count += 1
                flags.append(f"URL contains IP address: {url}")
            
            # Check for URL obfuscation
            if self._check_url_obfuscation(url):
                suspicious_url_count += 1
                flags.append(f"URL appears obfuscated: {url}")
            
            # Check for URL shorteners
            if self._is_url_shortener(domain):
                suspicious_url_count += 1
                flags.append(f"URL uses shortening service: {url}")
            
            # Check for misleading domains (e.g., paypal-secure.com)
            if self._check_misleading_domain(domain):
                suspicious_url_count += 1
                flags.append(f"URL contains misleading domain: {domain}")
        
        # Calculate score based on suspicious URLs
        if suspicious_url_count > 0:
            url_ratio = suspicious_url_count / len(urls)
            score += min(0.8, url_ratio)  # Cap at 0.8
        
        # Cap score at 1.0
        score = min(1.0, score)
        
        return {
            'score': score,
            'flags': flags
        }
    
    def _check_grammar_issues(self, text):
        """Simple check for grammar/spelling issues"""
        # This is a simplified check - in production, use a proper grammar checker
        common_errors = [
            r'\byour\b.*\byou\'re\b', r'\bthere\b.*\btheir\b', r'\bits\b.*\bit\'s\b',
            r'\bto\b.*\btoo\b', r'\bthen\b.*\bthan\b'
        ]
        
        # Check for mixed case sentences
        sentences = re.split(r'[.!?]+', text)
        mixed_case = any(self._has_mixed_case(s) for s in sentences if len(s) > 20)
        
        # Check for common grammatical errors
        grammar_errors = any(re.search(pattern, text, re.IGNORECASE) for pattern in common_errors)
        
        return mixed_case or grammar_errors
    
    def _has_mixed_case(self, sentence):
        """Check if a sentence has unusual mixed case words"""
        words = re.findall(r'\b\w+\b', sentence)
        mixed_case_words = sum(1 for w in words if re.search(r'[a-z][A-Z]', w))
        return mixed_case_words > 2
    
    def _check_url_obfuscation(self, url):
        """Check for URL obfuscation techniques"""
        # Check for hex encoding
        if re.search(r'%[0-9A-Fa-f]{2}', url):
            return True
        
        # Check for excessive subdomains
        parsed = urlparse(url)
        if parsed.netloc.count('.') > 3:
            return True
        
        # Check for misleading protocol (http vs https)
        if 'http' in parsed.netloc:
            return True
        
        # Check for very long URLs
        if len(url) > 100:
            return True
        
        return False
    
    def _is_url_shortener(self, domain):
        """Check if domain is a known URL shortener"""
        shorteners = [
            'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly',
            'is.gd', 'buff.ly', 'adf.ly', 'tiny.cc', 'lnkd.in'
        ]
        return domain.lower() in shorteners
    
    def _check_misleading_domain(self, domain):
        """Check for domains that might be misleading"""
        trusted_brands = [
            'paypal', 'apple', 'microsoft', 'amazon', 'google',
            'facebook', 'bank', 'netflix', 'instagram', 'twitter'
        ]
        
        # Check for brand names in non-official domains
        domain_lower = domain.lower()
        
        for brand in trusted_brands:
            if brand in domain_lower:
                # Check if it's not the official domain
                official_domains = {
                    'paypal': 'paypal.com',
                    'apple': 'apple.com',
                    'microsoft': 'microsoft.com',
                    'amazon': 'amazon.com',
                    'google': 'google.com',
                    'facebook': 'facebook.com',
                    'netflix': 'netflix.com',
                    'instagram': 'instagram.com',
                    'twitter': 'twitter.com'
                }
                
                if brand in official_domains and domain_lower != official_domains[brand]:
                    return True
        
        return False
