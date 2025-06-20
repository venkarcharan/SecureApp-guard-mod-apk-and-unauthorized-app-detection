# SecureApp-guard-mod-apk-and-unauthorized-app-detection
APK Analyzer is a Flask-based web tool that detects modified or unauthorized Android APKs using machine learning. It analyzes permissions, services, cryptographic methods, and native code to assess risk and potential tampering

# 🛡️ APK Analyzer – Detect Modified & Unauthorized Android Apps

**APK Analyzer** is a web-based tool that leverages machine learning to detect tampered or unauthorized Android APK files. It performs static code analysis to evaluate risk levels based on permissions, cryptographic usage, native code, and more.

---

## ✨ Features

- 🔍 Upload APK files via an intuitive drag-and-drop interface
- ⚙️ Analyze APK structure using static code analysis
- 🤖 Machine learning-based detection (Random Forest classifier)
- 🔐 Evaluate for signs of tampering or malicious modification
- 📊 Detailed output includes:
  - Permission count
  - Activity, service, receiver, and provider count
  - Total methods and cryptographic usage
  - Native code detection
  - File statistics

---

## ⚙️ Setup Instructions

1. **Create a virtual environment (optional but recommended):**
```bash
python -m venv venv
# On Windows:
venv\Scripts\activate
# On Unix/Mac:
source venv/bin/activate

Install dependencies:
pip install -r requirements.txt

Prepare necessary folders:
python app.py

Running the Application
Start the Flask server:

python app.py

Open your browser and navigate to:
http://localhost:5000

Upload an APK file through the web interface

Wait for the analysis to complete

Review the results:

✅ Risk level (Low / Medium / High)

🔢 Confidence score

📋 Feature-based breakdown

🛠️ Status and recommendations

🧠 Technical Overview
Uses Androguard for APK parsing and static analysis

Random Forest classifier to evaluate potential modification

Extracted features include component counts, crypto usage, and native methods

Robust error handling and automatic APK cleanup after analysis

🔐 Security Considerations
Files are processed locally only – no external file transmission

APKs are automatically deleted post-analysis

Intended for educational, research, and security auditing only

📦 Requirements
Python 3.7 or above

Flask

NumPy

scikit-learn

androguard

Joblib

A modern web browser with JavaScript enabled


