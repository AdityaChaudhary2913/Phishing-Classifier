from flask import Flask, render_template, url_for, request, send_file, jsonify
from src.exception import CustomException
from src.logger import logging as lg
import os,sys
from joblib import load
import re
import socket
import whois
from datetime import datetime
from urllib.parse import urlparse

from src.pipeline.train_pipeline import TrainingPipeline
from src.pipeline.predict_pipeline import PredictionPipeline

app = Flask(__name__)

model = load('trained_model/model.pkl')

def extract_features(url: str) -> list:
    features = []
    features.append(1 if re.search(r'\d+\.\d+\.\d+\.\d+', url) else 0)
    features.append(len(url))
    features.append(1 if re.search(r'bit\.ly|goo\.gl|tinyurl\.com|is\.gd|t\.co|ow\.ly', url) else 0)
    features.append(1 if '@' in url else 0)
    features.append(1 if '//' in urlparse(url).path[1:] else 0)
    domain = urlparse(url).netloc
    features.append(1 if '-' in domain else 0)
    features.append(len(domain.split('.')) - 2)
    try:
        if 'https' in url:
            features.append(1)
        else:
            features.append(0)
    except:
        features.append(0)
    try:
        domain_info = whois.whois(domain)
        expiration_date = domain_info.expiration_date
        registration_length = (expiration_date - datetime.now()).days if expiration_date else 0
        features.append(1 if registration_length >= 365 else 0)
    except:
        features.append(0)
    features.append(1 if re.search(r'favicon.ico', url) else 0)
    features.append(1 if re.search(r':\d+', url) else 0)
    features.append(1 if 'https' in domain else 0)
    features.append(1 if len(re.findall(r'http[s]?://', url)) > 1 else 0)
    features.append(1 if re.search(r'<a[^>]+href="http[s]?://', url) else 0)
    features.append(1 if re.search(r'<link[^>]+href="http[s]?://', url) else 0)
    features.append(1 if re.search(r'action="http[s]?://', url) else 0)
    features.append(1 if re.search(r'mailto:', url) else 0)
    features.append(1 if domain not in url else 0)
    features.append(1 if re.search(r'http[s]?://[^/]+//', url) else 0)
    features.append(1 if re.search(r'onmouseover', url) else 0)
    features.append(1 if re.search(r'oncontextmenu', url) else 0)
    features.append(1 if re.search(r'window.open', url) else 0)
    features.append(1 if re.search(r'<iframe', url) else 0)
    try:
        creation_date = domain_info.creation_date
        domain_age = (datetime.now() - creation_date).days if creation_date else 0
        features.append(1 if domain_age >= 365 else 0)
    except:
        features.append(0)
    try:
        socket.gethostbyname(domain)
        features.append(0)  # DNS Record exists
    except:
        features.append(1)  # No DNS Record
    features.append(1)  # Placeholder, needs integration with web traffic service
    features.append(1)  # Placeholder, requires third-party API
    features.append(1)  # Placeholder, requires Google API integration
    features.append(1 if re.search(r'<a href=', url) else 0)
    features.append(1 if 'phish' in url.lower() else 0)
    return features

@app.route("/")
def home():
    return render_template('home.html')

@app.route("/train")
def train_route():
    try:
        train_pipeline = TrainingPipeline()
        train_pipeline.run_pipeline()
        return render_template('training.html')
    except Exception as e:
        raise CustomException(e,sys)

@app.route("/url_classifier", methods=['POST', 'GET'])
def url_classifier():
    if request.method == 'POST':
        data = request.get_json()
        url = data.get('url')
        # if not url:
        #     return jsonify(error="Please enter a URL"), 400
        # features = extract_features(url)
        features = [1,0,-1,1,1,-1,1,1,-1,1,1,-1,1,0,1,-1,1,1,0,1,1,1,1,1,-1,1,1,1,0,1]
        prediction = model.predict([features])[0]
        result = 'Phishing' if prediction == 1 else 'Legitimate'
        return jsonify(result=result, url=url)
    
    # For GET requests or page load
    return render_template('url_classifier.html')

@app.route('/predict', methods=['POST', 'GET'])
def predict():
    try:
        if request.method == 'POST':
            prediction_pipeline = PredictionPipeline(request)
            prediction_file_detail = prediction_pipeline.run_pipeline()
            lg.info("prediction completed. Downloading prediction file.")
            return send_file(prediction_file_detail.prediction_file_path, download_name= prediction_file_detail.prediction_file_name, as_attachment= True)
        else:
            return render_template('prediction.html')
    except Exception as e:
        raise CustomException(e,sys)
    
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug= True)