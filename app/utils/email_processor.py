import re
import email
from bs4 import BeautifulSoup
import tldextract
from email_validator import validate_email, EmailNotValidError

class EmailProcessor:
    """
    Class for processing and extracting information from email content
    """
    
    def __init__(self):
        # Common phishing keywords to look for
        self.suspicious_keywords = [
            'urgent', 'verify', 'account', 'suspended', 'update', 'confirm',
            'security', 'bank', 'payment', 'click', 'link', 'password',
            'credential', 'login', 'access', 'limited', 'offer', 'prize',
            'won', 'winner', 'lottery', 'official', 'alert', 'attention'
        ]
        
        # URL regex pattern
        self.url_pattern = re.compile(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+')
    
    def process(self, content, sender='', subject=''):
        """
        Process email content and extract relevant information
        
        Args:
            content (str): Raw email content
            sender (str, optional): Email sender
            subject (str, optional): Email subject
            
        Returns:
            dict: Processed email information
        """
        # Parse email if content appears to be in email format
        if content.startswith('From:') or content.startswith('Return-Path:') or 'Content-Type:' in content:
            try:
                parsed_email = email.message_from_string(content)
                
                # Extract headers if not provided
                if not sender and 'From' in parsed_email:
                    sender = parsed_email['From']
                if not subject and 'Subject' in parsed_email:
                    subject = parsed_email['Subject']
                
                # Extract body
                body = self._get_email_body(parsed_email)
            except Exception:
                # If parsing fails, treat content as plain text
                body = content
        else:
            # Treat content as plain text
            body = content
        
        # Clean and normalize text
        clean_text = self._clean_text(body)
        
        # Extract URLs
        urls = self._extract_urls(body)
        
        # Process sender information
        sender_info = self._analyze_sender(sender)
        
        # Identify suspicious keywords
        suspicious_words = self._identify_suspicious_keywords(clean_text)
        
        # Return processed information
        return {
            'sender': sender,
            'sender_info': sender_info,
            'subject': subject,
            'body': clean_text,
            'urls': urls,
            'suspicious_keywords': suspicious_words
        }
    
    def _get_email_body(self, parsed_email):
        """Extract body from parsed email"""
        body = ""
        
        if parsed_email.is_multipart():
            for part in parsed_email.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition"))
                
                # Skip attachments
                if "attachment" in content_disposition:
                    continue
                
                # Get the payload
                payload = part.get_payload(decode=True)
                if payload:
                    if content_type == "text/plain":
                        body += payload.decode('utf-8', errors='replace')
                    elif content_type == "text/html":
                        soup = BeautifulSoup(payload.decode('utf-8', errors='replace'), 'html.parser')
                        body += soup.get_text(separator=' ', strip=True)
        else:
            # Handle non-multipart emails
            payload = parsed_email.get_payload(decode=True)
            if payload:
                content_type = parsed_email.get_content_type()
                if content_type == "text/plain":
                    body = payload.decode('utf-8', errors='replace')
                elif content_type == "text/html":
                    soup = BeautifulSoup(payload.decode('utf-8', errors='replace'), 'html.parser')
                    body = soup.get_text(separator=' ', strip=True)
        
        return body
    
    def _clean_text(self, text):
        """Clean and normalize text"""
        if not text:
            return ""
            
        # Convert to string if not already
        if not isinstance(text, str):
            text = str(text)
            
        # Remove HTML tags if present
        if '<' in text and '>' in text:
            soup = BeautifulSoup(text, 'html.parser')
            text = soup.get_text(separator=' ', strip=True)
        
        # Normalize whitespace
        text = re.sub(r'\s+', ' ', text).strip()
        
        return text
    
    def _extract_urls(self, text):
        """Extract URLs from text"""
        if not text:
            return []
            
        # Find all URLs
        urls = self.url_pattern.findall(text)
        
        # Process each URL
        processed_urls = []
        for url in urls:
            # Extract domain information
            extracted = tldextract.extract(url)
            domain = f"{extracted.domain}.{extracted.suffix}"
            
            processed_urls.append({
                'url': url,
                'domain': domain,
                'subdomain': extracted.subdomain,
                'is_ip_address': self._is_ip_address(extracted.domain)
            })
        
        return processed_urls
    
    def _analyze_sender(self, sender):
        """Analyze sender email address"""
        if not sender:
            return {'valid': False, 'domain': None, 'reason': 'No sender provided'}
        
        # Extract email from "Name <email@example.com>" format
        email_match = re.search(r'<([^>]+)>', sender)
        email_address = email_match.group(1) if email_match else sender
        
        try:
            # Validate email
            valid_email = validate_email(email_address, check_deliverability=False)
            
            # Extract domain information
            extracted = tldextract.extract(valid_email.domain)
            domain = f"{extracted.domain}.{extracted.suffix}"
            
            return {
                'valid': True,
                'domain': domain,
                'normalized_address': valid_email.normalized,
                'is_free_provider': self._is_free_email_provider(domain),
                'is_ip_address': self._is_ip_address(extracted.domain)
            }
        except EmailNotValidError as e:
            return {'valid': False, 'domain': None, 'reason': str(e)}
    
    def _identify_suspicious_keywords(self, text):
        """Identify suspicious keywords in text"""
        if not text:
            return []
            
        text_lower = text.lower()
        found_keywords = []
        
        for keyword in self.suspicious_keywords:
            if keyword in text_lower:
                found_keywords.append(keyword)
        
        return found_keywords
    
    def _is_free_email_provider(self, domain):
        """Check if domain is a common free email provider"""
        free_providers = [
            'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 
            'aol.com', 'mail.com', 'protonmail.com', 'icloud.com'
        ]
        return domain.lower() in free_providers
    
    def _is_ip_address(self, domain):
        """Check if domain part is an IP address"""
        ip_pattern = re.compile(r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$')
        return bool(ip_pattern.match(domain))
