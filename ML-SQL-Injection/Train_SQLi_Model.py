from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import pandas as pd
import pickle

# Load dataset
df = pd.read_csv("Good_and_Bad_requests.csv")
X = df.drop("class", axis=1)
y = df["class"].apply(lambda x: 1 if x == "bad" else 0)

# Split into train/test
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train
clf = RandomForestClassifier(n_estimators=100, random_state=42)
clf.fit(X_train, y_train)

# Evaluate
y_pred = clf.predict(X_test)
print(classification_report(y_test, y_pred))

# Save model
with open("SQLi_Model.pkl", "wb") as f:
    pickle.dump(clf, f)
