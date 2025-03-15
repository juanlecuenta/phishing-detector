# AI-Powered Phishing Email Detector

A web-based tool that leverages Natural Language Processing (NLP) techniques to analyze emails and determine their phishing risk. The system evaluates email content, sender reputation, and embedded links to generate a risk score.

## Features

- **Email Analysis**: Upload or paste email content for immediate analysis
- **Risk Scoring**: Get a comprehensive risk assessment with detailed breakdown
- **BERT-based Detection**: Utilizes a fine-tuned BERT model for advanced phishing detection (when available)
- **Rule-Based Fallback**: Employs heuristic rules as a reliable fallback mechanism
- **Sender Verification**: Analyzes sender reputation and domain information
- **Link Analysis**: Identifies and evaluates suspicious URLs within emails

## Getting Started

### Prerequisites

- Python 3.8+ (tested with Python 3.12)
- pip (Python package manager)
- Virtual environment (recommended)

### Installation

1. Clone the repository:
```
git clone <repository-url>
cd phishing-detector
```

2. Create and activate a virtual environment (recommended):
```
# On Windows
python -m venv venv
venv\Scripts\activate

# On macOS/Linux
python -m venv venv
source venv/bin/activate
```

3. Install dependencies:
```
pip install -r requirements.txt
```

4. (Optional) Install advanced model dependencies:
```
pip install transformers torch
```
This step enables the BERT-based phishing detection model. If these packages are not installed, the application will automatically fall back to the rule-based model.

### Running the Application

You can run the application using either of the following methods:

#### Method 1: Using run.py (Standard)
```
python run.py
```

#### Method 2: Using simple_app.py (Alternative)
If you encounter any issues with the standard method, you can use the simplified version:
```
python simple_app.py
```

5. Open your browser and navigate to:
```
http://localhost:5000
```

## Project Structure

```
phishing-detector/
├── app/
│   ├── models/         # Model implementations
│   │   ├── model_loader.py  # Loads either BERT or rule-based model
│   ├── static/         # Static files (CSS, JS)
│   ├── templates/      # HTML templates
│   ├── utils/          # Utility functions
│   └── __init__.py     # Flask application initialization
├── tests/              # Test cases
├── run.py              # Standard application entry point
├── simple_app.py       # Alternative simplified application
├── requirements.txt    # Project dependencies
└── README.md           # Project documentation
```

## Detection Models

The application supports two phishing detection models:

1. **BERT-based Model**: A fine-tuned BERT model from HuggingFace (`ealvaradob/bert-finetuned-phishing`) that provides advanced phishing detection capabilities. This model requires the `transformers` and `torch` packages.

2. **Rule-based Model**: A heuristic approach that analyzes email content for suspicious keywords, URL patterns, and urgent language. This model is used as a fallback when the BERT model is not available.

The system automatically selects the best available model at runtime.

## API Endpoints

- `POST /api/analyze-email`: Analyze email content for phishing risk
- `GET /api/health`: Health check endpoint

## Troubleshooting

If you encounter any issues:

1. Ensure you're using a compatible Python version (3.8+ recommended, tested with 3.12)
2. Make sure your virtual environment is activated
3. Try using the simplified application version: `python simple_app.py`
4. If Flask installation issues occur, try: `pip install flask==2.0.3 werkzeug==2.2.3`
5. If you encounter errors related to transformers or PyTorch, the application will automatically use the rule-based model instead

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- HuggingFace for providing the pre-trained BERT model
- The open-source community for various libraries and tools used in this project
