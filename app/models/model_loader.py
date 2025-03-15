import os
import re
import random

# Set to False since we're not using transformers in this simplified version
USE_TRANSFORMERS = False

# Singleton pattern to ensure model is loaded only once
_model_instance = None

def get_model():
    """
    Get or initialize the phishing detection model
    
    Returns:
        SimplePhishingModel: An instance of the phishing detection model
    """
    global _model_instance
    
    if _model_instance is None:
        _model_instance = SimplePhishingModel()
    
    return _model_instance


class PhishingModel:
    """Base class for phishing detection models"""
    
    def predict_phishing_probability(self, text):
        """
        Predict the probability that an email is a phishing attempt
        
        Args:
            text (str): The email text to analyze
            
        Returns:
            float: Probability between 0 and 1
        """
        raise NotImplementedError("Subclasses must implement predict_phishing_probability")


class SimplePhishingModel(PhishingModel):
    """A simplified phishing detection model that uses rule-based heuristics"""
    
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
    
    def predict_phishing_probability(self, text):
        """
        Predict the probability that an email is a phishing attempt using simple rules
        
        Args:
            text (str): The email text to analyze
            
        Returns:
            float: Probability between 0 and 1
        """
        if not text:
            return 0.5
        
        score = 0.0
        text_lower = text.lower()
        
        # Check for suspicious keywords
        keyword_count = sum(1 for keyword in self.suspicious_keywords if keyword in text_lower)
        keyword_score = min(0.6, keyword_count * 0.05)  # Cap at 0.6
        score += keyword_score
        
        # Check for URLs and suspicious URL patterns
        urls = re.findall(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+', text)
        if urls:
            # More URLs might indicate phishing
            url_count_score = min(0.3, len(urls) * 0.1)  # Cap at 0.3
            score += url_count_score
            
            # Check for suspicious URL patterns
            for url in urls:
                url_lower = url.lower()
                pattern_matches = sum(1 for pattern in self.suspicious_url_patterns 
                                     if re.search(pattern, url_lower))
                if pattern_matches > 0:
                    score += min(0.4, pattern_matches * 0.1)  # Cap at 0.4
        
        # Check for urgent language
        urgent_patterns = [
            r'urgent', r'immediate', r'attention required', r'act now',
            r'limited time', r'expires', r'deadline', r'asap'
        ]
        urgent_count = sum(1 for pattern in urgent_patterns if re.search(pattern, text_lower))
        if urgent_count > 0:
            score += min(0.3, urgent_count * 0.1)  # Cap at 0.3
        
        # Add a small random factor to make it more realistic
        score += random.uniform(-0.05, 0.05)
        
        # Ensure score is between 0 and 1
        return max(0.0, min(1.0, score))
