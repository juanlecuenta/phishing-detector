import os
import re
import random

# Set to True to use the BERT model from HuggingFace if available
USE_TRANSFORMERS = True

# Check if transformers are installed
try:
    import transformers
    import torch
    TRANSFORMERS_AVAILABLE = True
    print("Transformers and PyTorch are available")
except ImportError:
    TRANSFORMERS_AVAILABLE = False
    print("Transformers or PyTorch not available, using simple model")

# Singleton pattern to ensure model is loaded only once
_model_instance = None

def get_model():
    """
    Get or initialize the phishing detection model
    
    Returns:
        PhishingModel: An instance of the phishing detection model
    """
    global _model_instance
    
    if _model_instance is None:
        if USE_TRANSFORMERS and TRANSFORMERS_AVAILABLE:
            try:
                _model_instance = BERTPhishingModel()
                print("Successfully loaded BERT model for phishing detection")
            except Exception as e:
                print(f"Error loading BERT model: {str(e)}. Falling back to simple model.")
                _model_instance = SimplePhishingModel()
        else:
            _model_instance = SimplePhishingModel()
            print("Using simple rule-based model for phishing detection")
    
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


# Only define the BERTPhishingModel if transformers are available
if TRANSFORMERS_AVAILABLE:
    class BERTPhishingModel(PhishingModel):
        """Phishing detection model using a fine-tuned BERT model from HuggingFace"""
        
        def __init__(self):
            """Initialize the BERT model for phishing detection"""
            try:
                from transformers import AutoTokenizer, AutoModelForSequenceClassification
                import torch
                
                # Load the tokenizer and model
                self.tokenizer = AutoTokenizer.from_pretrained("ealvaradob/bert-finetuned-phishing")
                self.model = AutoModelForSequenceClassification.from_pretrained("ealvaradob/bert-finetuned-phishing")
                self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
                self.model.to(self.device)
                self.model.eval()  # Set model to evaluation mode
                
                # Maximum sequence length for BERT
                self.max_length = 512
                
                # Flag to indicate successful initialization
                self.initialized = True
                
            except Exception as e:
                print(f"Error initializing BERT model: {str(e)}")
                self.initialized = False
        
        def predict_phishing_probability(self, text):
            """
            Predict the probability that an email is a phishing attempt using BERT
            
            Args:
                text (str): The email text to analyze
                
            Returns:
                float: Probability between 0 and 1
            """
            if not self.initialized:
                # Fall back to simple model if BERT failed to initialize
                return SimplePhishingModel().predict_phishing_probability(text)
            
            if not text:
                return 0.5
            
            try:
                import torch
                
                # Truncate text if it's too long
                if len(text) > 10000:
                    text = text[:10000]
                
                # Tokenize the input
                inputs = self.tokenizer(
                    text,
                    return_tensors="pt",
                    truncation=True,
                    max_length=self.max_length,
                    padding="max_length"
                )
                
                # Move inputs to the same device as the model
                inputs = {k: v.to(self.device) for k, v in inputs.items()}
                
                # Perform inference
                with torch.no_grad():
                    outputs = self.model(**inputs)
                    logits = outputs.logits
                    
                    # Convert logits to probabilities using softmax
                    probabilities = torch.nn.functional.softmax(logits, dim=1)
                    
                    # Get the probability of phishing (assuming index 1 is phishing)
                    phishing_probability = probabilities[0, 1].item()
                    
                    return phishing_probability
                    
            except Exception as e:
                print(f"Error during BERT prediction: {str(e)}")
                # Fall back to simple model if prediction fails
                return SimplePhishingModel().predict_phishing_probability(text)


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
        urgent_score = min(0.3, urgent_count * 0.1)  # Cap at 0.3
        score += urgent_score
        
        # Add a small random factor to make it more realistic
        score += random.uniform(-0.05, 0.05)
        
        # Ensure score is between 0 and 1
        return max(0.0, min(1.0, score))
