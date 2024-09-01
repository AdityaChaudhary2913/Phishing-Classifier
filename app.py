from flask import Flask, render_template, url_for, request, send_file, jsonify
from src.exception import CustomException
from src.logger import logging as lg
import os,sys
from joblib import load
import re
import socket
import pandas as pd
import whois
from datetime import datetime
from urllib.parse import urlparse
import requests
from bs4 import BeautifulSoup

from src.pipeline.train_pipeline import TrainingPipeline
from src.pipeline.predict_pipeline import PredictionPipeline

app = Flask(__name__)

try:    
    model = load('trained_model/model.pkl')
except Exception as e:
    model = None

def extract_features(url: str) -> list:
    parsed_url = urlparse(url)
    features = []

    # 1. Check if IP address is in URL
    try:
        if socket.gethostbyname(parsed_url.hostname):
            features.append(1)
    except socket.error:
        features.append(-1)

    # 2. URL Length
    if len(url) < 54:
        features.append(-1)
    elif 54 <= len(url) <= 75:
        features.append(0)
    else:
        features.append(1)

    # 3. URL Shortening Service
    short_services = ['bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 't.co']
    if any(service in url for service in short_services):
        features.append(-1)
    else:
        features.append(1)

    # 4. Having @ symbol
    features.append(1 if '@' in url else -1)

    # 5. Double slash redirecting
    position = url.rfind("//")
    if position > 7:
        features.append(-1)
    else:
        features.append(1)

    # 6. Prefix-Suffix
    features.append(-1 if '-' in parsed_url.netloc else 1)

    # 7. Having Sub Domain
    subdomains = parsed_url.hostname.split('.')
    if len(subdomains) > 3:
        features.append(1)
    elif len(subdomains) == 3:
        features.append(0)
    else:
        features.append(-1)

    # 8. SSL final state
    try:
        response = requests.get(url)
        if response.history:
            features.append(-1)
        elif 'https' in response.url:
            features.append(1)
        else:
            features.append(0)
    except:
        features.append(-1)

    # 9. Domain registration length
    try:
        domain_info = whois.whois(url)
        expiration_date = domain_info.expiration_date
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]
        if (expiration_date - datetime.now()).days >= 365:
            features.append(1)
        else:
            features.append(-1)
    except:
        features.append(-1)

    # 10. Favicon
    try:
        response = requests.get(url + '/favicon.ico')
        favicon_url = urlparse(response.url)
        domain = urlparse(url).netloc
        features.append(1 if favicon_url.netloc == domain else -1)
    except:
        features.append(-1)

    # 11. Port
    # Standard web port check
    features.append(1 if parsed_url.port == 80 or parsed_url.port == 443 else -1)

    # 12. HTTPS token in the domain part
    features.append(-1 if 'https' in parsed_url.netloc else 1)

    # 13. Request URL
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    external_links = [link for link in soup.find_all('a', href=True) if urlparse(link['href']).netloc and urlparse(link['href']).netloc != urlparse(url).netloc]
    features.append(1 if len(external_links) > 5 else -1)

    # 14. URL of Anchor
    total_links = soup.find_all('a', href=True)
    if not total_links:
        features.append(1)
    else:
        external_links = [link for link in total_links if urlparse(link['href']).netloc and urlparse(link['href']).netloc != urlparse(url).netloc]
        percentage = len(external_links) / len(total_links)
        features.append(-1 if percentage > 0.67 else 1)

    # 15. Links in tags
    total_tags = soup.find_all(['link', 'script'], href=True) + soup.find_all(['link', 'script'], src=True)
    external_tags = [tag for tag in total_tags if urlparse(tag.get('href', tag.get('src', ''))).netloc and urlparse(tag.get('href', tag.get('src', ''))).netloc != urlparse(url).netloc]
    percentage = len(external_tags) / len(total_tags) if total_tags else 0
    features.append(-1 if percentage > 0.22 else 1)

    # 16. SFH
    features.append(1)

    # 17. Submitting to email
    features.append(1)

    # 18. Abnormal URL
    features.append(-1 if parsed_url.netloc != urlparse(requests.get(url).url).netloc else 1)

    # 19. Redirect
    features.append(1 if len(response.history) > 1 else 0)

    # 20. on_mouseover
    mouse_overs = soup.find_all(onmouseover=True)
    features.append(-1 if any("window.status" in mo['onmouseover'] for mo in mouse_overs) else 1)

    # 21. RightClick
    if 'event.button==2' in response.text or 'contextmenu' in response.text:
        features.append(-1)
    else:
        features.append(1)

    # 22. popUpWidnow
    if "window.open(" in response.text:
        features.append(-1)
    else:
        features.append(1)

    # 23. Iframe
    iframes = soup.find_all('iframe', style=lambda value: value and 'display:none' in value)
    features.append(-1 if iframes else 1)

    # 24. Age of Domain
    try:
        creation_date = domain_info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if (datetime.now() - creation_date).days > 180:
            features.append(1)
        else:
            features.append(-1)
    except:
        features.append(-1)

    # 25. DNSRecord
    features.append(1)

    # 26. Web Traffic
    # Placeholder, needs actual implementation
    features.append(1)

    # 27. Page Rank
    # Placeholder, needs actual implementation
    features.append(1)

    # 28. Google Index
    # Placeholder, needs actual implementation
    features.append(1)

    # 29. Links pointing to page
    # Placeholder, needs actual implementation
    features.append(1)

    # 30. Statistical report
    # Placeholder, needs actual implementation
    features.append(1)

    # Return the complete list of features
    return features

@app.route("/")
def home():
    return render_template('home.html', name=model)

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
        if not url:
            return jsonify(error="Please enter a URL"), 400
        features = extract_features(url)
        feature_names = [
            'having_IP_Address', 'URL_Length', 'Shortining_Service', 'having_At_Symbol',
            'double_slash_redirecting', 'Prefix_Suffix', 'having_Sub_Domain', 'SSLfinal_State',
            'Domain_registeration_length', 'Favicon', 'port', 'HTTPS_token',
            'Request_URL', 'URL_of_Anchor', 'Links_in_tags', 'SFH', 'Submitting_to_email',
            'Abnormal_URL', 'Redirect', 'on_mouseover', 'RightClick', 'popUpWidnow',
            'Iframe', 'age_of_domain', 'DNSRecord', 'web_traffic', 'Page_Rank',
            'Google_Index', 'Links_pointing_to_page', 'Statistical_report'
        ]
        features_df = pd.DataFrame([features], columns=feature_names)
        # features = [1,0,-1,1,1,-1,1,1,-1,1,1,-1,1,0,1,-1,1,1,0,1,1,1,1,1,-1,1,1,1,0,1]
        prediction = model.predict(features_df)[0]
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