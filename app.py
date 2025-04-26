from flask import Flask, render_template, url_for, request, session, send_file, jsonify, redirect
from src.exception import CustomException
from src.logger import logging as lg
import sys
import os
from joblib import load
import pandas as pd
from src.utils.extract_features import ExtractFeatures

from src.pipeline.train_pipeline import TrainingPipeline
from src.pipeline.predict_pipeline import PredictionPipeline

from src.constant import ADMIN_ID, ADMIN_PASSWORD

from pymongo import MongoClient


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
            db['classified_urls'].insert_one({'url': url, 'result': result, 'features': object.features, 'verified': False})
        
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
    
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug= True)
    

# http://paypal.com.cgi.bin.webscr.cmd.login.submit.dispatch.5885d80a13c03faee8dcbcd55a50598f04d34b4bf5tt1.mediareso.com/secure-code90/security/
# https://paypal.com.us.cgi.bin.webscr.cmd.login.submit.bx3digitallp.com/Review/3a3e3c4dba5e5cc4407a5694adf1aa8e/

# [http://google.com-redirect@valimail.com](http://google.com-redirect@valimail.com/)

# [https://paypa1-login.com](https://paypa1-login.com/)

# [https://googl-search-results.com](https://googl-search-results.com/)
# [https://ebay-auction-alerts.com](https://ebay-auction-alerts.com/)
# [https://amazo0n-secure-checkout.com](https://amazo0n-secure-checkout.com/)