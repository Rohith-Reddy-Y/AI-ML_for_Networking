from gensim.models.doc2vec import Doc2Vec
from nltk.tokenize import word_tokenize
from urllib.parse import unquote
import numpy as np
import pickle
import base64
import xml.etree.ElementTree as ET

# Load models
model = Doc2Vec.load("lib/d2v.model")
models = {
    "DecisionTree": pickle.load(open("lib/DecisionTreeClassifier.sav", "rb")),
    "SVC": pickle.load(open("lib/SVC.sav", "rb")),
    "GaussianNB": pickle.load(open("lib/GaussianNB.sav", "rb")),
    "KNN": pickle.load(open("lib/KNeighborsClassifier.sav", "rb")),
    "RandomForest": pickle.load(open("lib/RandomForestClassifier.sav", "rb")),
    "MLP": pickle.load(open("lib/MLPClassifier.sav", "rb"))
}

weights = {
    "DecisionTree": 0.175,
    "SVC": 0.15,
    "GaussianNB": 0.05,
    "KNN": 0.075,
    "RandomForest": 0.25,
    "MLP": 0.3
}

def extract_xss_features(text):
    tokens = word_tokenize(text.lower())
    vec = model.infer_vector(tokens)
    feature_vec = vec

    # Tags
    tags = ['link','object','form','embed','ilayer','layer','style','applet','meta','img','iframe','marquee']
    tag_count = sum(text.count(t) for t in tags)

    # JS methods
    methods = ['exec','fromcharcode','eval','alert','getelementsbytagname','write','unescape','escape','prompt','onload','onclick','onerror','onpage','confirm']
    method_count = sum(text.count(m) for m in methods)

    js_count = text.count('.js')
    javascript_count = text.count('javascript')
    length = len(text)

    script_count = text.count('script') + text.count('<script') + text.count('&lt;script') + text.count('%3cscript') + text.count('%3c%73%63%72%69%70%74')

    special_count = sum(text.count(c) for c in ['&', '<', '>', '"', "'", '/', '%', '*', ';', '+', '=', '%3C'])

    http_count = text.count('http')

    feature_vec = np.append(feature_vec, [tag_count, method_count, js_count, javascript_count, length, script_count, special_count, http_count])
    return feature_vec

def parse_burp(file):
    results = []
    try:
        tree = ET.parse(file)
        root = tree.getroot()
        for item in root.findall('item'):
            request_data = item.findtext('request', default="")
            is_base64 = item.find('request').attrib.get('base64', 'false') == 'true'
            raw = base64.b64decode(request_data).decode(errors='ignore') if is_base64 else request_data

            # Parse HTTP Request
            lines = raw.splitlines()
            first_line = lines[0] if lines else ""
            if ' ' in first_line:
                method, path, *_ = first_line.split()
                results.append(path)
    except Exception as e:
        print("Error parsing log:", e)
    return results

testXSS = parse_burp("bad_requests.log")

X = [extract_xss_features(unquote(line.lower())) for line in testXSS]

xss_count, not_xss_count = 0, 0

for i, x in enumerate(X):
    score = sum(models[name].predict([x])[0] * weight for name, weight in weights.items())
    if score >= 0.5:
        print(f"\033[1;31;1mXSS\033[0;0m => {testXSS[i]}")
        xss_count += 1
    else:
        print(f"\033[1;32;1mNOT XSS\033[0;0m => {testXSS[i]}")
        not_xss_count += 1

print("\n*------------- RESULTS -------------*")
print(f"\033[1;31;1mXSS\033[0;0m => {xss_count}")
print(f"\033[1;32;1mNOT XSS\033[0;0m => {not_xss_count}")