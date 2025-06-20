from flask import Flask, render_template, url_for, request, session, send_file, jsonify, redirect
from src.exception import CustomException
from src.logger import logging as lg
import sys
import os, certifi
from bson import ObjectId
from joblib import load
import pandas as pd
from src.utils.extract_features import ExtractFeatures

from src.pipeline.train_pipeline import TrainingPipeline
from src.pipeline.predict_pipeline import PredictionPipeline

from src.constant import ADMIN_ID, ADMIN_PASSWORD

from pymongo import MongoClient

os.environ.setdefault("SSL_CERT_FILE", certifi.where())

app = Flask(__name__)
app.secret_key = os.getenv("SessionSecretKey")


# MongoDB Atlas connection
client = MongoClient(os.getenv("MONGODB_URL") )
db = client['phishing']



model = None
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(ROOT_DIR, 'trained_model', 'model.pkl')
try:    
    model = load(MODEL_PATH)
except Exception as e:
    model = None
    print(e)

@app.route("/")
def home():
    return render_template('home.html', name=model)

@app.route("/train")
def train_route():
    if not session.get('admin_logged_in'):
        return redirect(url_for('home')) 
    try:
        if not model:
            train_pipeline = TrainingPipeline()
            train_pipeline.run_pipeline()
        return render_template('training.html')
    except Exception as e:
        raise CustomException(e,sys)


@app.route("/admin_login", methods=['POST'])
def admin_login():
    data = request.get_json()
    admin_id = data.get('adminID')
    admin_password = data.get('adminPassword')

    if admin_id == ADMIN_ID and admin_password == ADMIN_PASSWORD:
        session['admin_logged_in'] = True
        return jsonify(success=True)
    else:
        session['admin_logged_in'] = False
        return jsonify(success=False)

@app.route("/logout")
def logout():
    session['admin_logged_in'] = False
    session.pop('admin_logged_in', None)
    return redirect(url_for('home'))

@app.route("/url_classifier", methods=['POST', 'GET'])
def url_classifier():
    if request.method == 'POST':
        data = request.get_json()
        url = data.get('url')
        if not url:
            return jsonify(error="Please enter a URL"), 400
        
        # Check if the URL has already been classified
        existing_entry = db['classified_urls'].find_one({'url': url})
        
        object = ExtractFeatures()
        object.extract_features(url)
        feature_names = [
            'having_IP_Address', 'URL_Length', 'Shortining_Service', 'having_At_Symbol',
            'double_slash_redirecting', 'Prefix_Suffix', 'having_Sub_Domain', 'SSLfinal_State',
            'Domain_registeration_length', 'Favicon', 'port', 'HTTPS_token',
            'Request_URL', 'URL_of_Anchor', 'Links_in_tags', 'SFH', 'Submitting_to_email',
            'Abnormal_URL', 'Redirect', 'on_mouseover', 'RightClick', 'popUpWidnow',
            'Iframe', 'age_of_domain', 'DNSRecord', 'web_traffic', 'Page_Rank',
            'Google_Index', 'Links_pointing_to_page', 'Statistical_report'
        ]
        features_df = pd.DataFrame([object.features], columns=feature_names)
        # features = [1,0,-1,1,1,-1,1,1,-1,1,1,-1,1,0,1,-1,1,1,0,1,1,1,1,1,-1,1,1,1,0,1]
        prediction = model.predict(features_df)[0]
        result = 'Phishing' if prediction == 0 else 'Legitimate'
        
        # Save to MongoDB
        if not existing_entry:
            db['classified_urls'].insert_one({'url': url, 'result': result, 'features': object.features})
        
        return jsonify(result=result, url=url)
    
    # For GET requests or page load
    return render_template('url_classifier.html')

@app.route("/report_incorrect", methods=['POST'])
def report_incorrect():
    data = request.get_json()
    url = data.get('url')
    result = data.get('result').split(" ")[-1]
    
    # Check if the URL already exists in the 'reported_urls' collection
    existing_report = db['reported_urls'].find_one({'url': url})
    
    if existing_report:
        return jsonify(message="This URL has already been reported."), 200
    
    object = ExtractFeatures()
    object.extract_features(url)

    # Save reported URL in a different collection
    db['reported_urls'].insert_one({'url': url, 'reported_result': result, 'features': object.features, 'verified': False})
    
    existing_entry_classified = db['classified_urls'].find_one({'url': url})
    if existing_entry_classified:
        db['classified_urls'].delete_one({'url': url})
    
    return jsonify(message="Reported successfully"), 200


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
    
@app.route("/admin/reported_urls")
def admin_url_verification():
    if not session.get('admin_logged_in'):
        return redirect(url_for('home'))
    reported_urls = list(db['reported_urls'].find({}))
    for url in reported_urls:
        url['_id'] = str(url['_id'])  # Convert ObjectId to string for template
    return render_template('url_verification.html', reported_urls=reported_urls)

@app.route("/admin/verify_url", methods=['POST'])
def admin_verify_url():
    if not session.get('admin_logged_in'):
        return jsonify(success=False, message="Unauthorized"), 401
    data = request.get_json()
    url_id = data.get('url_id')
    correct_result = data.get('correct_result')

    if not url_id or correct_result not in ['Legitimate', 'Phishing']:
        return jsonify(success=False, message="Invalid data"), 400

    try:
        # Fetch reported URL
        reported_url = db.reported_urls.find_one({'_id': ObjectId(url_id)})
        if not reported_url:
            return jsonify(success=False, message="URL not found"), 404

        # Remove from classified_urls if exists
        db.classified_urls.delete_one({'url': reported_url['url']})

        # Add to classified_urls
        classified_entry = {
            'url': reported_url['url'],
            'result': correct_result,
            'features': reported_url['features']
        }
        db.classified_urls.insert_one(classified_entry)

        # Prepare dataset entry
        feature_names = [
            'having_IP_Address', 'URL_Length', 'Shortining_Service', 'having_At_Symbol',
            'double_slash_redirecting', 'Prefix_Suffix', 'having_Sub_Domain', 'SSLfinal_State',
            'Domain_registeration_length', 'Favicon', 'port', 'HTTPS_token',
            'Request_URL', 'URL_of_Anchor', 'Links_in_tags', 'SFH', 'Submitting_to_email',
            'Abnormal_URL', 'Redirect', 'on_mouseover', 'RightClick', 'popUpWidnow',
            'Iframe', 'age_of_domain', 'DNSRecord', 'web_traffic', 'Page_Rank',
            'Google_Index', 'Links_pointing_to_page', 'Statistical_report'
        ]
        features = reported_url['features']
        if len(features) != len(feature_names):
            return jsonify(success=False, message="Features mismatch"), 400

        dataset_entry = {fn: features[i] for i, fn in enumerate(feature_names)}
        dataset_entry['Result'] = 1 if correct_result == 'Legitimate' else 0

        # Insert into dataset
        db.dataset.insert_one(dataset_entry)

        # Remove from reported_urls
        db.reported_urls.delete_one({'_id': ObjectId(url_id)})

        return jsonify(success=True, message="URL verified successfully")
    except Exception as e:
        return jsonify(success=False, message=str(e)), 500
    
@app.route("/admin/classified_urls")
def admin_classified_urls():
    if not session.get('admin_logged_in'):
        return redirect(url_for('home'))
    
    classified_urls = list(db.classified_urls.find({}))
    length = len(classified_urls)
    for url in classified_urls:
        url['_id'] = str(url['_id'])
    return render_template('classifydb_to_dataset.html', classified_urls=classified_urls, lngth=length)

@app.route("/admin/move_to_dataset", methods=['POST'])
def move_to_dataset():
    if not session.get('admin_logged_in'):
        return jsonify(success=False, message="Unauthorized"), 401

    try:
        # Get all classified URLs
        classified_urls = list(db.classified_urls.find({}))
        
        # Prepare feature names (should match your dataset schema)
        feature_names = [
            'having_IP_Address', 'URL_Length', 'Shortining_Service', 'having_At_Symbol',
            'double_slash_redirecting', 'Prefix_Suffix', 'having_Sub_Domain', 'SSLfinal_State',
            'Domain_registeration_length', 'Favicon', 'port', 'HTTPS_token',
            'Request_URL', 'URL_of_Anchor', 'Links_in_tags', 'SFH', 'Submitting_to_email',
            'Abnormal_URL', 'Redirect', 'on_mouseover', 'RightClick', 'popUpWidnow',
            'Iframe', 'age_of_domain', 'DNSRecord', 'web_traffic', 'Page_Rank',
            'Google_Index', 'Links_pointing_to_page', 'Statistical_report'
        ]

        # Convert classified URLs to dataset entries
        dataset_entries = []
        for url in classified_urls:
            if len(url['features']) != len(feature_names):
                continue  # Skip entries with mismatched features

            entry = {fn: url['features'][i] for i, fn in enumerate(feature_names)}
            entry['Result'] = 1 if url['result'] == 'Legitimate' else 0
            dataset_entries.append(entry)

        # Insert into dataset collection
        if dataset_entries:
            db.dataset.insert_many(dataset_entries)

        # Delete all classified URLs
        db.classified_urls.delete_many({})

        return jsonify(
            success=True,
            message=f"Moved {len(dataset_entries)} URLs to dataset"
        )
    except Exception as e:
        return jsonify(success=False, message=str(e)), 500
    
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug= True)
    

# http://paypal.com.cgi.bin.webscr.cmd.login.submit.dispatch.5885d80a13c03faee8dcbcd55a50598f04d34b4bf5tt1.mediareso.com/secure-code90/security/
# https://paypal.com.us.cgi.bin.webscr.cmd.login.submit.bx3digitallp.com/Review/3a3e3c4dba5e5cc4407a5694adf1aa8e/

# [http://google.com-redirect@valimail.com](http://google.com-redirect@valimail.com/)

# [https://paypa1-login.com](https://paypa1-login.com/)

# [https://googl-search-results.com](https://googl-search-results.com/)
# [https://ebay-auction-alerts.com](https://ebay-auction-alerts.com/)
# [https://amazo0n-secure-checkout.com](https://amazo0n-secure-checkout.com/)