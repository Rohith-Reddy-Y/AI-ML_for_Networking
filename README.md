# AI-ML for Networking	

<p align="center">	
  <img src="https://github.com/user-attachments/assets/d2226bd3-d614-45a4-987c-4990a544fe60" alt="Image 1" width="49%">	
  <img src="https://github.com/user-attachments/assets/d2a26625-4040-4145-9a7b-8d4126460684" alt="Image 2" width="49%">	
</p>	

This project implements an AI-driven solution for detecting SQL Injection (SQLi) and Cross-Site Scripting (XSS) attacks in network traffic using machine learning. It features a web interface for real-time threat detection, file upload analysis (CSV, PDF, DOCX, TXT), and detailed logging. The system uses pre-trained models (RandomForestClassifier, Doc2Vec) and integrates a Web Application Firewall (WAF) concept for enhanced security.	

Category: Network Security	

Prerequisites:	
- Python 3.9 or higher	
- Git for cloning the repository	
- Optional: Google API Key and Hugging Face API Token for AI threat analysis	

⚠️ Important Python Version Notice:	
✅ This project is tested and works best with Python versions between 3.9.x and 3.11.x.	
❌ Python 3.13 or higher is not supported and may result in errors like:	
```	
BackendUnavailable: Cannot import 'mesonpy'	
```	
👉 If you encounter such errors, please install Python 3.11.x from:	
https://www.python.org/downloads/release/python-3113/	
and recreate the virtual environment.	

Additional Skills (Recommended for Users):	
- Computer Systems Basics – CPU/Memory/Storage/NIC	
- Good hands-on experience on Linux	
- Programming skills in Python and/or C	
- Basics of AI/ML	

Problem Statement:	
Develop a machine learning-based solution to detect and prevent common web application attacks such as SQL Injection and XSS, with an easy-to-use web interface for real-time detection and file analysis.	

Installation:	

1. Clone the repository:	
```	
git clone https://github.com/Rohith-Reddy-Y/AI-ML_for_Networking.git	
```	

2. Navigate to the project directory:	
```	
cd AI-ML_for_Networking	
```	

3. Create and activate a virtual environment:	
```	
python -m venv venv	
```	
On Windows:	
```	
venv\Scripts\activate	
```	

4. Install dependencies:	
```	
pip install -r requirements.txt	
```	

5. Create a `.env` file in the `Attacks_Detection` directory (optional):	
```	
GOOGLE_API_KEY=your_google_api_key	
HF_API_TOKEN=your_hf_api_token	
```	

🚨 Troubleshooting (Common Issues & Fixes):	

| Issue                                           | Cause                                        | Solution                                  |	
|-----------------------------------------------|---------------------------------------------|-------------------------------------------|	
| `BackendUnavailable: Cannot import 'mesonpy'` | Using Python 3.13+ (unsupported version)     | Downgrade to **Python 3.11.x**            |	
| `No module named flask_limiter`                | Missing dependencies                        | Run: `pip install -r requirements.txt`    |	
| `RandomForestClassifier.sav not found`         | Model files not copied to correct folder     | Copy trained models to `Attacks_Detection/Models` |	

Training the Models:	

SQL Injection Model:	
1. Navigate to the `ML-SQL-Injection` directory:	
```	
cd ML-SQL-Injection	
```	

2. Run the Good_and_Bad_requests.py to generate the dataset:	
```	
python Good_and_Bad_requests.py	
```	
This processes `bad_requests.log` and `good_requests.log` to create `Good_and_Bad_requests_1.csv`.	

3. Train the RandomForestClassifier model:	
```	
python Train_SQLi_model.py	
```	
This saves the model to `ML-SQL-Injection/SQLi_Model.pkl`.	

XSS Model:	
1. Navigate to the `ML-XSS` directory:	
```	
cd ML-XSS	
```	

2. Run the training script in Jupyter Notebook:	
Make sure you have Jupyter installed:	
```	
pip install notebook	
```	
Then launch the notebook:	
```	
jupyter notebook XSS-Doc2Vec-ML-Classifier-checkpoint.ipynb	
```	
Run all the cells to train the model.	

This generates:	
- `ML-XSS/lib/d2v.model`	
- `ML-XSS/lib/RandomForestClassifier.sav` (best accuracy)	
- Other `.sav` models.	

Running the Application:	

Make sure to copy the following trained files into the `Attacks_Detection/Models` folder before running:	
- `d2v.model`	
- `RandomForestClassifier.sav`	
- `SQLi_Model.pkl`	

1. Activate the virtual environment:	
```	
source venv/bin/activate	
```	
On Windows:	
```	
venv\Scripts\activate	
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
http://localhost:5000	

Web Interface Features:	
- Enter a query for real-time SQLi/XSS detection.	
- Upload a file (`CSV`, `PDF`, `DOCX`, `TXT`) for batch analysis.	

Key Components:	

| Directory           | Description                        | Key Files                                           |	
|---------------------|------------------------------------|-----------------------------------------------------|	
| Attacks_Detection/   | Main application and models        | app.py, detection_log.txt, Templates/index.html, Models/*.sav, *.pkl, *.model, Data/*.csv |	
| ML-SQL-Injection/    | SQLi feature extraction and training | Log/*.log, Good_and_Bad_requests.py, Train_SQLi_model.py |	
| ML-XSS/              | XSS detection and training         | ML-XSS_Model_Testing.py, .ipynb_checkpoints/XSS-Doc2Vec-ML-Classifier-checkpoint.ipynb, lib/*.sav, *.txt |	
