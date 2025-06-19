
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
import chardet
import re
import warnings
# Suppress version warnings temporarily for clarity
warnings.filterwarnings("ignore", category=UserWarning)
# Download NLTK data
try:
    nltk.download('punkt')
    nltk.download('punkt_tab')
except Exception as e:
    print(f"Error downloading NLTK data: {e}")
    exit(1)
app = Flask(__name__)
# SQL Injection Detection: Feature Extraction (6 features)
badwords = ['sleep', 'drop', 'uid', 'uname', 'select', 'waitfor', 'delay', 'system', 'union', 'order by', 'group by', 'insert', 'update', 'delete']
sql_keywords = ['or', 'and', 'union', 'select', 'insert', 'update', 'delete']
def extract_sql_features(input_data):
    if not input_data or not isinstance(input_data, str):
        return [0] * 6  # Return zeros for 6 features
    try:
        input_data = unquote_plus(input_data.lower())
        # Count quotes and braces only if near SQL keywords with stricter context
        single_q = sum(1 for i, char in enumerate(input_data) if char == "'" and any(kw in input_data[max(0, i-10):i+10] for kw in sql_keywords))
        double_q = sum(1 for i, char in enumerate(input_data) if char == '"' and any(kw in input_data[max(0, i-10):i+10] for kw in sql_keywords))
        dashes = input_data.count("--") if any(kw in input_data for kw in sql_keywords) else 0
        braces = sum(1 for i, char in enumerate(input_data) if char == "(" and any(kw in input_data[max(0, i-10):i+10] for kw in sql_keywords))
        spaces = input_data.count(" ") if any(kw in input_data for kw in sql_keywords) else 0
        badwords_count = sum(input_data.count(word) for word in badwords if word in input_data)
        features = [single_q, double_q, dashes, braces, spaces, badwords_count]
        print(f"SQL Features for '{input_data}': {features} (Length: {len(features)})")  # Debugging
        return features
    except Exception as e:
        print(f"Error in SQL feature extraction: {e}")
        return [0] * 6
# XSS Detection: Advanced Feature Extraction (26 features)
try:
    d2v_model = Doc2Vec.load("lib/d2v.model")
except FileNotFoundError:
    print("Error: 'lib/d2v.model' not found. Please ensure it is in the 'lib' directory.")
    exit(1)
except Exception as e:
    print(f"Error loading Doc2Vec model: {e}")
    exit(1)
def getVec(text):
    features = []
    for line in text:
        if not line or not isinstance(line, str):
            test_data = ["default"]
        else:
            test_data = word_tokenize(unquote(line).lower())
        try:
            v1 = d2v_model.infer_vector(test_data)
            if len(v1) != 20:
                raise ValueError("Doc2Vec vector length mismatch")
        except Exception as e:
            print(f"Doc2Vec inference error: {e}")
            v1 = [0] * 20  # Fallback vector, 20 dimensions
        featureVec = v1
        try:
            lineDecode = unquote(line)
            lowerStr = str(lineDecode).lower()
            # Focus on XSS-specific features
            feature1 = sum(lowerStr.count(tag) for tag in ['script', '<script', 'iframe', 'onerror', 'onload'])
            feature2 = sum(lowerStr.count(method) for method in ['alert', 'eval', 'exec', 'write', 'unescape'])
            feature3 = lowerStr.count('.js')
            feature4 = lowerStr.count('javascript')
            feature5 = len(lowerStr) if feature1 > 0 or feature2 > 0 else 0  # Length only if XSS-like
            feature6 = sum(1 for char in ['<', '>', '&'] if char in lowerStr and ('script' in lowerStr or 'javascript' in lowerStr))
            feature_vec = np.append(featureVec, [feature1, feature2, feature3, feature4, feature5, feature6])
            if len(feature_vec) != 26:
                raise ValueError("XSS feature vector length mismatch")
            features.append(feature_vec)
            print(f"XSS Features for '{line}': {feature_vec} (Length: {len(feature_vec)})")  # Debugging
        except Exception as e:
            print(f"Error in XSS feature extraction: {e}")
            features.append(np.append([0] * 20, [0] * 6))
    return features
# Load or Train Models
def load_or_train_sql_model():
    try:
        with open("sqli_model_test1.pkl", "rb") as f:
            sql_model = pickle.load(f)
            sql_scaler = pickle.load(f)
    except (FileNotFoundError, EOFError, Exception) as e:
        if not os.path.exists("demo_good_and_bad_requests_test4.csv"):
            print("Error: 'demo_good_and_bad_requests_test4.csv' not found. Ensure it exists in the directory.")
            exit(1)
        
        try:
            df = pd.read_csv("demo_good_and_bad_requests_test4.csv")
            print("Class distribution:", df['class'].value_counts())
            
            # Fix labeling if needed (example correction)
            df['class'] = df['class'].apply(lambda x: 1 if x.lower() == 'bad' else 0)
            if len(df['class'].unique()) < 2:
                raise ValueError("Dataset must contain both 'good' and 'bad' classes.")
            
            X = df[['single_q', 'double_q', 'dashes', 'braces', 'spaces', 'badwords']].values
            y = df['class'].values
            X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
            sql_scaler = StandardScaler()
            X_train_scaled = sql_scaler.fit_transform(X_train)
            X_test_scaled = sql_scaler.transform(X_test)
            sql_model = LogisticRegression(random_state=42)
            sql_model.fit(X_train_scaled, y_train)
            print(f"SQL Model Accuracy: {accuracy_score(y_test, sql_model.predict(X_test_scaled))}")
            with open("sqli_model_test1.pkl", "wb") as f:
                pickle.dump(sql_model, f)
                pickle.dump(sql_scaler, f)
        except Exception as e:
            print(f"Error training SQL model: {e}")
            exit(1)
    return sql_model, sql_scaler
def load_xss_model():
    try:
        with open("lib/RandomForestClassifier.sav", "rb") as f:
            xss_model = pickle.load(f)
        if not hasattr(xss_model, 'estimators_') or xss_model.estimators_ is None:
            raise ValueError("Loaded RandomForestClassifier is not fitted.")
        return xss_model
    except FileNotFoundError:
        print("Error: 'lib/RandomForestClassifier.sav' not found. Please ensure it is in the 'lib' directory.")
        exit(1)
    except Exception as e:
        print(f"Error loading RandomForestClassifier: {e}")
        exit(1)
sql_model, sql_scaler = load_or_train_sql_model()
xss_model = load_xss_model()
# Serve the Front-End Website
@app.route('/')
def home():
    try:
        return render_template('index.html')
    except Exception as e:
        return jsonify({"error": f"Template error: {e}"}), 500
# Real-Time Detection Endpoint (API)
@app.route('/detect', methods=['GET', 'POST'])
def detect():
    try:
        method = request.method
        if method == 'POST':
            input_data = request.form.get('query', '') or request.form.get('cfile', '')
        else:
            input_data = request.args.get('query', '')
        if not input_data:
            raise ValueError("No input query provided")
        
        try:
            decoded_data = unquote_plus(input_data)
        except Exception as e:
            decoded_data = input_data
            print(f"Decoding error: {e}")
        
        # SQL Injection Detection
                # SQL Injection Detection
        sql_features = extract_sql_features(decoded_data)
        if len(sql_features) != 6:
            raise ValueError(f"SQL features invalid: {len(sql_features)} features, expected 6")
        
        # ✅ Fix false positives: Skip prediction if all features are zero
        if sum(sql_features) == 0:
            sql_result = "No SQL Injection"
            sql_prediction = 0
        else:
            sql_features_scaled = sql_scaler.transform([sql_features])
            sql_prediction = sql_model.predict(sql_features_scaled)[0]
            sql_result = "SQL Injection Detected" if sql_prediction == 1 else "No SQL Injection"
        # XSS Detection
        xss_features = getVec([decoded_data])
        if len(xss_features[0]) != 26:
            raise ValueError(f"XSS features invalid: {len(xss_features[0])} features, expected 26")
        xss_prediction = xss_model.predict(xss_features)[0]
        xss_result = "XSS Detected" if xss_prediction == 1 else "No XSS"
        # Log the request with detailed debug info
        log_entry = f"Request Method: {method}\nInput Query: {input_data}\nSQL Features: {sql_features}\nSQL Prediction: {sql_prediction}\nXSS Features: {xss_features[0]}\nXSS Prediction: {xss_prediction}\nSQL Result: {sql_result}\nXSS Result: {xss_result}\n\n"
        with open("detection_log.txt", "a") as f:
            f.write(log_entry)
        return jsonify({"sql_injection": sql_result, "xss": xss_result})
    except Exception as e:
        error_msg = f"Error during detection: {str(e)}"
        log_entry = f"Request Method: {method}\nInput Query: {input_data}\nError: {error_msg}\n\n"
        with open("detection_log.txt", "a") as f:
            f.write(log_entry)
        return jsonify({"sql_injection": error_msg, "xss": error_msg}), 500
# Handle favicon to avoid 404 errors
@app.route('/favicon.ico')
def favicon():
    return '', 204
if __name__ == '__main__':
    try:
        app.run(host='127.0.0.1', port=5000, debug=True)
    except Exception as e:
        print(f"Server error: {e}")
        exit(1)
