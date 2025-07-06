# AI-ML_for_Networking

## Project Description
This project implements an AI-driven solution for detecting SQL Injection (SQLi) and Cross-Site Scripting (XSS) attacks in network traffic using machine learning. It features a web interface for real-time threat detection, file upload analysis (CSV, PDF, DOCX, TXT), and detailed logging. The system uses pre-trained models (RandomForestClassifier, Doc2Vec) and integrates a Web Application Firewall (WAF) concept for enhanced security.

### Category
Network Security

---

## Prerequisites

- Python 3.9 or higher  
- Git for cloning the repository  
- Linux environment (recommended for compatibility)  
- Optional: Google API Key and Hugging Face API Token for AI threat analysis  

---

## Additional Skills (Recommended for Users)

- Computer Systems Basics – CPU/Memory/Storage/NIC  
- Good hands-on experience on Linux  
- Programming skills in Python and/or C  
- Basics of AI/ML  

---

## Problem Statement

Description:  
Develop a machine learning-based solution to detect and prevent common web application attacks such as SQL Injection and XSS, with an easy-to-use web interface for real-time detection and file analysis.

---

## Installation

1. **Clone the repository:**  
   ```
   git clone https://github.com/your-username/AI-ML_for_Networking.git
   ```

2. **Navigate to the project directory:**  
   ```
   cd AI-ML_for_Networking
   ```

3. **Create and activate a virtual environment:**  
   ```
   python -m venv venv
   source venv/bin/activate    # On Windows: venv\Scripts\activate
   ```

4. **Install dependencies:**  
   ```
   pip install -r requirements.txt
   ```

5. **Create a `.env` file in the `Attacks_Detection` directory (optional):**  
   ```
   GOOGLE_API_KEY=your_google_api_key
   HF_API_TOKEN=your_hf_api_token
   ```

---

## Training the Models

### SQL Injection Model:

1. Navigate to the `ML-SQL-Injection` directory:
   ```
   cd ML-SQL-Injection
   ```

2. Run the log parser to generate the dataset:
   ```
   python log_parser.py
   ```
   ➔ This processes `bad_requests.log` and `good_requests.log` to create `data/demo_good_and_bad_requests.csv`.

3. Train the RandomForestClassifier model:
   ```
   python train_sqli_model.py
   ```
   ➔ This saves the model to `Attacks_Detection/models/sqli_model.pkl`.

---

### XSS Model:

1. Navigate to the `ML-XSS` directory:
   ```
   cd ML-XSS
   ```

2. Run the training script:
   ```
   python XSS-Doc2Vec-ML-Classifier.py
   ```
   ➔ This generates `Attacks_Detection/models/d2v.model` and `Attacks_Detection/models/RandomForestClassifier.sav`.

---

## Running the Application

1. Activate the virtual environment:
   ```
   source venv/bin/activate   # On Windows: venv\Scripts\activate
   ```

2. Navigate to the `Attacks_Detection` directory:
   ```
   cd Attacks_Detection
   ```

3. Run the application:
   ```
   python app.py
   ```

4. Access the web interface at:  
   [http://localhost:5000](http://localhost:5000)

---

## Web Interface Features:

- Enter a query for real-time SQLi/XSS detection.
- Upload a file (`CSV`, `PDF`, `DOCX`, `TXT`) for batch analysis.

---

## Key Components

| Directory           | Description                        | Key Files                                           |
|---------------------|------------------------------------|-----------------------------------------------------|
| Attacks_Detection/   | Main application and models        | app.py, templates/index.html, models/*.sav, models/*.pkl |
| ML-SQL-Injection/    | SQLi feature extraction and training | log_parser.py, train_sqli_model.py                  |
| ML-XSS/              | XSS detection and training         | ml_xss.py, XSS-Doc2Vec-ML-Classifier.py             |
| data/                | Datasets for training/testing      | demo_good_and_bad_requests.csv, httplog.csv, testXSS.txt, testNORM.txt |
| docs/                | Documentation                     | README.md, Project_Report.tex, Proposed Architecture Diagram.docx |
