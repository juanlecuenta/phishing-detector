# AI-Powered Phishing Email Detector

A web-based tool that leverages Natural Language Processing (NLP) techniques to analyze emails and determine their phishing risk. The system evaluates email content, sender reputation, and embedded links to generate a risk score.

## Features

- **Email Analysis**: Upload or paste email content for immediate analysis
- **Risk Scoring**: Get a comprehensive risk assessment with detailed breakdown
- **Rule-Based Detection**: Utilizes heuristic rules to identify phishing indicators
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

4. Open your browser and navigate to:
```
http://localhost:5000
```

## Project Structure

```
phishing-detector/
├── app/
│   ├── models/         # Model implementations
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

## API Endpoints

- `POST /api/analyze-email`: Analyze email content for phishing risk
- `GET /api/health`: Health check endpoint

## Troubleshooting

If you encounter any issues:

1. Ensure you're using a compatible Python version (3.8+ recommended, tested with 3.12)
2. Make sure your virtual environment is activated
3. Try using the simplified application version: `python simple_app.py`
4. If Flask installation issues occur, try: `pip install flask==2.0.3 werkzeug==2.2.3`

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Enron dataset for legitimate email examples
- PhishTank for phishing email examples
