import base64
from urllib.parse import unquote, unquote_plus
from flask import Flask, request, render_template, jsonify
import pandas as pd
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score
import pickle
from gensim.models.doc2vec import Doc2Vec
from nltk.tokenize import word_tokenize
import nltk
import os

# Download NLTK data
nltk.download('punkt')

app = Flask(__name__)

# SQL Injection Detection: Feature Extraction
badwords = ['sleep', 'drop', 'uid', 'uname', 'select', 'waitfor', 'delay', 'system', 'union', 'order by', 'group by']

def parse_raw_http_request(rawreq):
    try:
        raw = rawreq.decode('utf-8')
    except:
        raw = rawreq
    headers = {}
    sp = raw.split('\r\n\r\n', 1)
    if len(sp) > 1 and sp[1] != "":
        head = sp[0]
        body = sp[1]
    else:
        head = sp[0]
        body = ""
    c1 = head.split('\n', head.count('\n'))
    method = c1[0].split(' ', 2)[0]
    path = c1[0].split(' ', 2)[1]
    for i in range(1, head.count('\n') + 1):
        slice1 = c1[i].split(': ', 1)
        if slice1[0] != "":
            try:
                headers[slice1[0]] = slice1[1]
            except:
                pass
    return headers, method, body, path

def extract_sql_features(method, path_enc, body_enc, headers):
    badwords_count = 0
    path = unquote_plus(path_enc)
    body = unquote(body_enc)
    single_q = path.count("'") + body.count("'")
    double_q = path.count('"') + body.count('"')
    dashes = path.count("--") + body.count("--")
    braces = path.count("(") + body.count("(")
    spaces = path.count(" ") + body.count(" ")
    for word in badwords:
        badwords_count += path.count(word) + body.count(word)
        for header in headers:
            badwords_count += headers[header].count(word)
    return [single_q, double_q, dashes, braces, spaces, badwords_count]

# XSS Detection: Feature Extraction
try:
    d2v_model = Doc2Vec.load("lib/d2v.model")
except FileNotFoundError:
    print("Error: 'lib/d2v.model' not found. Please ensure it is in the 'lib' directory.")
    exit(1)

def getVec(text):
    features = []
    for line in text:
        test_data = word_tokenize(line.lower())
        v1 = d2v_model.infer_vector(test_data)
        featureVec = v1
        lineDecode = unquote(line)
        lowerStr = str(lineDecode).lower()
        feature1 = sum(lowerStr.count(tag) for tag in ['link', 'object', 'form', 'embed', 'ilayer', 'layer', 'style', 'applet', 'meta', 'img', 'iframe', 'marquee'])
        feature2 = sum(lowerStr.count(method) for method in ['exec', 'fromcharcode', 'eval', 'alert', 'getelementsbytagname', 'write', 'unescape', 'escape', 'prompt', 'onload', 'onclick', 'onerror', 'onpage', 'confirm'])
        feature3 = lowerStr.count('.js')
        feature4 = lowerStr.count('javascript')
        feature5 = len(lowerStr)
        feature6 = sum(lowerStr.count(script) for script in ['script', '<script', '%3cscript', '%3c%73%63%72%69%70%74'])
        feature7 = sum(lowerStr.count(char) for char in ['&', '<', '>', '"', '\'', '/', '%', '*', ';', '+', '=', '%3C'])
        feature8 = lowerStr.count('http')
        featureVec = np.append(featureVec, [feature1, feature2, feature3, feature4, feature5, feature6, feature7, feature8])
        features.append(featureVec)
    return features

# Load or Train Models
def load_or_train_sql_model():
    try:
        with open("sql_injection_model.pkl", "rb") as f:
            sql_model = pickle.load(f)
            sql_scaler = pickle.load(f)
    except (FileNotFoundError, EOFError):
        if not os.path.exists("demo_good_and_bad_requests.csv"):
            try:
                good_df = pd.read_csv("demo_good_requests.csv")
                bad_df = pd.read_csv("demo_bad_responses.csv")
                combined_df = pd.concat([good_df, bad_df], ignore_index=True)
                combined_df.to_csv("demo_good_and_bad_requests.csv", index=False)
                print("Combined dataset created: demo_good_and_bad_requests.csv")
                print("Class distribution:", combined_df['class'].value_counts())
            except FileNotFoundError as e:
                print(f"Error: {e}. Ensure 'demo_good_requests.csv' and 'demo_bad_responses.csv' are in the directory.")
                exit(1)
        
        try:
            df = pd.read_csv("demo_good_and_bad_requests.csv")
        except FileNotFoundError:
            print("Error: 'demo_good_and_bad_requests.csv' not found.")
            exit(1)
        
        print("Class distribution:", df['class'].value_counts())
        
        if len(df['class'].unique()) < 2:
            raise ValueError("Dataset must contain both 'good' and 'bad' classes.")
        
        X = df[['single_q', 'double_q', 'dashes', 'braces', 'spaces', 'badwords']].values
        y = df['class'].apply(lambda x: 1 if x.lower() == 'bad' else 0).values
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        sql_scaler = StandardScaler()
        X_train_scaled = sql_scaler.fit_transform(X_train)
        X_test_scaled = sql_scaler.transform(X_test)
        sql_model = LogisticRegression(random_state=42)
        sql_model.fit(X_train_scaled, y_train)
        print(f"SQL Model Accuracy: {accuracy_score(y_test, sql_model.predict(X_test_scaled))}")
        with open("sql_injection_model.pkl", "wb") as f:
            pickle.dump(sql_model, f)
            pickle.dump(sql_scaler, f)
    return sql_model, sql_scaler

def load_xss_model():
    try:
        with open("lib/RandomForestClassifier.sav", "rb") as f:
            xss_model = pickle.load(f)
    except FileNotFoundError:
        print("Error: 'lib/RandomForestClassifier.sav' not found. Please ensure it is in the 'lib' directory.")
        exit(1)
    return xss_model

sql_model, sql_scaler = load_or_train_sql_model()
xss_model = load_xss_model()

# Serve the Front-End Website
@app.route('/')
def home():
    return render_template('index.html')

# Real-Time Detection Endpoint (API)
@app.route('/detect', methods=['GET', 'POST'])
def detect():
    try:
        method = request.method
        path = request.path
        headers = {k: v for k, v in request.headers.items()}
        body = request.get_data().decode('utf-8', errors='ignore')
        raw_request = f"{method} {path} HTTP/1.1\r\n"
        for key, value in headers.items():
            raw_request += f"{key}: {value}\r\n"
        raw_request += "\r\n" + body

        headers, method, body, path = parse_raw_http_request(raw_request.encode('utf-8'))

        # SQL Injection Detection
        sql_features = extract_sql_features(method, path, body, headers)
        sql_features_scaled = sql_scaler.transform([sql_features])
        sql_prediction = sql_model.predict(sql_features_scaled)[0]
        sql_result = "SQL Injection Detected" if sql_prediction == 1 else "No SQL Injection"

        # XSS Detection
        query = body if body else path
        xss_features = getVec([query])
        xss_prediction = xss_model.predict(xss_features)[0]
        xss_result = "XSS Detected" if xss_prediction == 1 else "No XSS"

        log_entry = f"Request: {raw_request}\nSQL: {sql_result}\nXSS: {xss_result}\n\n"
        with open("detection_log.txt", "a") as f:
            f.write(log_entry)

        return jsonify({"sql_injection": sql_result, "xss": xss_result})
    except Exception as e:
        error_msg = f"Error during detection: {str(e)}"
        log_entry = f"Request: {raw_request}\nError: {error_msg}\n\n"
        with open("detection_log.txt", "a") as f:
            f.write(log_entry)
        return jsonify({"error": error_msg}), 500

# Handle favicon to avoid 404 errors
@app.route('/favicon.ico')
def favicon():
    return '', 204

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)