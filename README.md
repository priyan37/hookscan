# HookScan

A Python-based phishing detection tool that analyzes URLs to identify potential phishing threats.

## Features
- Checks if a domain is flagged by Google Safe Browsing
- Identifies shortened URLs
- Checks SSL certificate validity
- Determines if the domain is indexed by Google
- Analyzes domain age to detect newly created suspicious sites
- Provides a risk score based on multiple security factors

## Installation

### Prerequisites
Ensure you have the following installed:
- Python 3.8 or later
- Git

### Clone the Repository
```bash
git clone https://github.com/priyan37/hookscan.git
cd hookscan
```

### Create a Virtual Environment (Optional but Recommended)
```bash
python -m venv venv
source venv/bin/activate   
```

### Install Required Dependencies
```bash
pip install -r requirements.txt
```

## Usage
```bash
python phishing_detection.py
```
Follow the on-screen instructions to enter a URL and analyze it.

## Dependencies
This project uses the following Python libraries:
- `requests`
- `whois`
- `beautifulsoup4`
- `rich`
- `urllib3`

Make sure all dependencies are installed using:
```bash
pip install -r requirements.txt
```

## API Key Setup
To enable **Google Safe Browsing** checks, replace `your_api_key_here` in `phishing_detection.py` with a valid API key from [Google Safe Browsing API](https://developers.google.com/safe-browsing/v4/get-started).

## License
This project is licensed under the MIT License.

## Contribution
Feel free to submit pull requests or report issues in the repository.

---
Created by Priyadharshan Vadivel
