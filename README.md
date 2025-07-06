AI-ML_for_Networking

Project Description
This project implements an AI-driven solution for detecting SQL Injection (SQLi) and Cross-Site Scripting (XSS) attacks in network traffic using machine learning. It features a web interface for real-time threat detection, file upload analysis (CSV, PDF, DOCX, TXT), and detailed logging. The system uses pre-trained models (RandomForestClassifier, Doc2Vec) and integrates a Web Application Firewall (WAF) concept for enhanced security.
Prerequisites

Python 3.9 or higher
Git for cloning the repository
Linux environment (recommended for compatibility)
Optional: Google API Key and Hugging Face API Token for AI threat analysis

Installation

Clone the repository:git clone https://github.com/your-username/AI-ML_for_Networking.git


Navigate to the project directory:cd AI-ML_for_Networking


Create a virtual environment:python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate


Install dependencies:pip install -r requirements.txt


Create a .env file in the Attacks_Detection directory with API keys (optional):GOOGLE_API_KEY=your_google_api_key
HF_API_TOKEN=your_hf_api_token



Training the Models
SQL Injection Model

Navigate to the ML-SQL-Injection directory:cd ML-SQL-Injection


Run the log parser to generate the dataset:python log_parser.py

This processes bad_requests.log and good_requests.log to create data/demo_good_and_bad_requests.csv.
Train the RandomForestClassifier model:python train_sqli_model.py

This saves the model to Attacks_Detection/models/sqli_model.pkl.

XSS Model

Navigate to the ML-XSS directory:cd ML-XSS


Run the training script (converted from the notebook):python XSS-Doc2Vec-ML-Classifier.py

This generates Attacks_Detection/models/d2v.model and Attacks_Detection/models/RandomForestClassifier.sav.

Running the Application

Activate the virtual environment:source venv/bin/activate  # On Windows: venv\Scripts\activate


Navigate to the Attacks_Detection directory:cd Attacks_Detection


Run the main application:python app.py


Access the web interface at http://localhost:5000.
Use the interface to:
Enter a query for real-time SQLi/XSS detection.
Upload a file (CSV, PDF, DOCX, TXT) for batch analysis.



Key Components



Directory
Description
Key Files



Attacks_Detection/
Main application and models
app.py, templates/index.html, models/d2v.model, models/RandomForestClassifier.sav, models/sqli_model.pkl


ML-SQL-Injection/
SQLi feature extraction and training
log_parser.py, train_sqli_model.py


ML-XSS/
XSS detection and training
ml_xss.py, XSS-Doc2Vec-ML-Classifier.py


data/
Datasets for training and testing
demo_good_and_bad_requests.csv, httplog.csv, testXSS.txt, testNORM.txt


docs/
Documentation
README.md, Project_Report.tex, Proposed Architecture Diagram.docx

