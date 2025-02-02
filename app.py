from flask import Flask, request, jsonify
from flask_cors import CORS
import pickle
import pandas as pd
import joblib
import logging
from extract_features import extract_url_features
from dotenv import load_dotenv
import os
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
CORS(app)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Load the model and encoders
try:
    with open("rf_model.pkl", 'rb') as f:
        rf_model = pickle.load(f)
    le = joblib.load('tld_encoder.pkl')
    scaler = joblib.load('scaler.pkl')
    logging.info("Model and encoders loaded successfully.")
except Exception as e:
    logging.error(f"Error loading model or encoders: {e}")
    raise e

@app.route('/check-phishing', methods=['POST'])
def check_phishing():
    try:
        data = request.get_json()
        url = data.get('url')
        if not url:
            return jsonify({'error': 'Missing URL parameter'}), 400
        
        logging.info(f"Received URL: {url}")
        
        # Extract features
        features = extract_url_features(url,api_key = os.getenv("api_key"))
        df_test = pd.DataFrame([features])
        
        # Encode categorical data
        df_test['TLD'] = df_test['TLD'].apply(lambda x: le.transform([x])[0] if x in le.classes_ else -1)
        
        # Scale features
        df_test = scaler.transform(df_test)
        feature_columns = [
            'URLLength', 'DomainLength', 'TLD', 'CharContinuationRate',
            'TLDLegitimateProb', 'TLDLength', 'NoOfSubDomain', 'LetterRatioInURL',
            'NoOfDegitsInURL', 'DegitRatioInURL', 'NoOfOtherSpecialCharsInURL',
            'SpacialCharRatioInURL', 'IsHTTPS', 'LineOfCode', 'LargestLineLength',
            'HasTitle', 'DomainTitleMatchScore', 'HasFavicon', 'Robots',
            'IsResponsive', 'HasDescription', 'NoOfPopup', 'NoOfiFrame',
            'HasExternalFormSubmit', 'HasSocialNet', 'HasSubmitButton',
            'HasHiddenFields', 'Bank', 'Pay', 'HasCopyrightInfo', 'NoOfImage',
            'NoOfCSS', 'NoOfJS', 'NoOfSelfRef', 'NoOfEmptyRef', 'NoOfExternalRef'
        ]
        df_test = pd.DataFrame(df_test, columns=feature_columns)
        
        # Make prediction
        rf_prob = rf_model.predict_proba(df_test)[0]
        is_phishing = rf_prob[0] > 0.60
        
        logging.info(f"Phishing Probability: {rf_prob[0]:.4f}, Detected: {is_phishing}")
        
        return jsonify({
            'is_phishing': bool(is_phishing),
            'probability': float(rf_prob[0])
        })
    except Exception as e:
        logging.error(f"Error processing request: {e}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)
