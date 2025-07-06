import base64
import csv
import xml.etree.ElementTree as ET
from urllib.parse import unquote_plus, unquote
import pandas as pd

# Process bad requests
badwords = ['sleep', 'drop', 'uid', 'uname', 'select', 'waitfor', 'delay', 'system', 'union', 'order by', 'group by', 'insert', 'update', 'delete']
log_path_bad = 'Log/bad_requests.log'
category_bad = "bad"

def extract_features(method, path_enc, body_enc, headers, category):
    path = unquote_plus(path_enc)
    body = unquote(body_enc)
    single_q = path.count("'") + body.count("'")
    double_q = path.count('"') + body.count('"')
    dashes = path.count("--") + body.count("--")
    braces = path.count("(") + body.count("(")
    spaces = path.count(" ") + body.count(" ")
    badwords_count = sum(path.lower().count(word) + body.lower().count(word) for word in badwords)
    for header in headers.values():
        for word in badwords:
            badwords_count += header.lower().count(word)
    return [single_q, double_q, dashes, braces, spaces, badwords_count, category]

def parse_burp_log(file_path, category):
    features = []
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
        for item in root.findall("item"):
            try:
                method = item.findtext("method", default="GET")
                path = item.findtext("path", default="/")
                request_base64 = item.find("request").attrib.get("base64", "false") == "true"
                request_data = item.findtext("request", default="")
                raw = base64.b64decode(request_data) if request_base64 else request_data.encode()

                # Minimal HTTP parsing
                lines = raw.decode(errors='ignore').split("\n")
                headers = {}
                body = ""
                found_blank = False
                for line in lines[1:]:
                    if line.strip() == "":
                        found_blank = True
                        continue
                    if not found_blank:
                        if ":" in line:
                            key, value = line.split(":", 1)
                            headers[key.strip()] = value.strip()
                    else:
                        body += line.strip()

                features.append(extract_features(method, path, body, headers, category))
            except Exception as e:
                print("Error parsing item:", e)
    except Exception as e:
        print("Failed to parse XML log:", e)
    return features

# Write bad requests to CSV
with open("temp_bad_responses.csv", "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["single_q", "double_q", "dashes", "braces", "spaces", "badwords", "class"])
    data_bad = parse_burp_log(log_path_bad, category_bad)
    writer.writerows(data_bad)

print("✅ Bad request feature extraction complete.")

# Process good requests
log_path_good = 'Log/good_requests.log'
category_good = "good"

# Write good requests to CSV
with open("temp_good_responses.csv", "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["single_q", "double_q", "dashes", "braces", "spaces", "badwords", "class"])
    data_good = parse_burp_log(log_path_good, category_good)
    writer.writerows(data_good)

print("✅ Good request feature extraction complete.")

# Combine both CSVs into one
df1 = pd.read_csv("temp_bad_responses.csv")
df2 = pd.read_csv("temp_good_responses.csv")
combined = pd.concat([df1, df2], ignore_index=True)
combined.to_csv("Good_and_Bad_requests_1.csv", index=False)

print("✅ Combined dataset saved as Good_and_Bad_requests_1.csv")