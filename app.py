import os
from flask import Flask, render_template, request, jsonify, make_response
from werkzeug.middleware.proxy_fix import ProxyFix
import numpy as np
from sklearn.ensemble import RandomForestClassifier
import hashlib
import zipfile
import androguard.core.bytecodes.apk as apk
from androguard.core.bytecodes.dvm import DalvikVMFormat
from androguard.core.analysis.analysis import Analysis
import joblib
import warnings
warnings.filterwarnings('ignore')

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 500MB max file size

# Error handlers
@app.errorhandler(413)
def request_entity_too_large(error):
    return jsonify({
        'error': 'File is too large. Maximum size is 500MB.',
        'details': 'Please try uploading a smaller file or contact support if you need to analyze larger APKs.'
    }), 413

@app.errorhandler(500)
def internal_server_error(error):
    return jsonify({'error': 'Internal server error occurred'}), 500

@app.errorhandler(Exception)
def handle_exception(error):
    return jsonify({'error': str(error)}), 500

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize the ML model
model = RandomForestClassifier(n_estimators=100, random_state=42)

def extract_features(apk_path):
    """Extract features from APK file for ML analysis."""
    features = {
        'permissions': 0,
        'activities': 0,
        'services': 0,
        'receivers': 0,
        'providers': 0,
        'total_methods': 0,
        'crypto_methods': 0,
        'native_methods': 0,
        'total_files': 0,
        'dex_count': 0
    }
    
    try:
        # Load APK
        a = apk.APK(apk_path)
        d = DalvikVMFormat(a.get_dex())
        dx = Analysis(d)
        
        # Basic APK information
        features['permissions'] = len(list(a.get_permissions()))
        features['activities'] = len(list(a.get_activities()))
        features['services'] = len(list(a.get_services()))
        features['receivers'] = len(list(a.get_receivers()))
        features['providers'] = len(list(a.get_providers()))
        
        # Code analysis
        methods = list(dx.get_methods())
        features['total_methods'] = len(methods)
        features['crypto_methods'] = sum(1 for m in methods if 'crypto' in str(m).lower())
        features['native_methods'] = sum(1 for m in methods if m.is_native())
        
        # File analysis
        with zipfile.ZipFile(apk_path, 'r') as zip_ref:
            files = zip_ref.namelist()
            features['total_files'] = len(files)
            features['dex_count'] = sum(1 for f in files if f.endswith('.dex'))
            
        # Calculate APK hash
        with open(apk_path, 'rb') as f:
            features['file_hash'] = hashlib.sha256(f.read()).hexdigest()
            
        return list(features.values())[:-1]  # Exclude hash from features
    
    except Exception as e:
        print(f"Error extracting features: {str(e)}")
        return None

def analyze_apk(apk_path):
    """Analyze APK file and return detection results."""
    try:
        features = extract_features(apk_path)
        
        if features is None:
            return {
                'status': 'error',
                'message': 'Failed to analyze APK file'
            }
        
        # Convert features to numpy array for prediction
        features_array = np.array(features).reshape(1, -1)
        
        # Make prediction (returns probability of being modified)
        try:
            prediction_prob = model.predict_proba(features_array)[0][1]
        except:
            # If model not trained, use heuristic approach
            prediction_prob = (features[0] > 50) * 0.5 + (features[2] > 10) * 0.3 + (features[6] > 1000) * 0.2
        
        # Determine risk level
        if prediction_prob < 0.3:
            risk_level = "Low"
            status = "Likely legitimate"
        elif prediction_prob < 0.7:
            risk_level = "Medium"
            status = "Potentially modified"
        else:
            risk_level = "High"
            status = "Likely modified"
        
        return {
            'status': status,
            'risk_level': risk_level,
            'confidence': round(prediction_prob * 100, 2),
            'features': {
                'permissions': features[0],
                'activities': features[1],
                'services': features[2],
                'total_methods': features[6],
                'crypto_methods': features[7],
                'native_methods': features[8]
            }
        }
    except Exception as e:
        return {
            'status': 'error',
            'message': f'Analysis error: {str(e)}'
        }

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    try:
        if 'apk' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400
        
        file = request.files['apk']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        if not file.filename.endswith('.apk'):
            return jsonify({'error': 'Please upload an APK file'}), 400
        
        # Save uploaded file
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        try:
            file.save(filepath)
            
            # Analyze the APK
            result = analyze_apk(filepath)
            
            # Clean up
            if os.path.exists(filepath):
                os.remove(filepath)
                
            response = make_response(jsonify(result))
            response.headers['Content-Type'] = 'application/json'
            return response
            
        except Exception as e:
            # Clean up
            if os.path.exists(filepath):
                os.remove(filepath)
            return jsonify({'error': f'Error analyzing APK: {str(e)}'}), 500
            
    except Exception as e:
        return jsonify({'error': f'Server error: {str(e)}'}), 500

if __name__ == '__main__':
    app.run(debug=True) 