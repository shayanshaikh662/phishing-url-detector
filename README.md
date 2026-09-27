# PhishGuard - Phishing URL Detector

PhishGuard is a web application that uses a trained machine learning
model (Random Forest) to analyze a URL and estimate whether it is
**SAFE** or **PHISHING**. It was built as an academic / college
cybersecurity project.

> **Disclaimer:** Machine-learning predictions are not guaranteed. Do
> not enter passwords, payment information, or other sensitive data on
> suspicious websites, regardless of what this tool reports.

---

## 1. Project Description

PhishGuard lets a user paste a URL into a web form. The backend
extracts a set of numeric features from that URL (length, number of
special characters, presence of an IP address, use of HTTPS, and so
on), feeds them into a Random Forest Classifier trained with
scikit-learn, and returns a SAFE / PHISHING prediction along with a
confidence percentage. Every scan is logged to a local SQLite
database, and the app shows a scan history page and a simple
dashboard.

## 2. Features

- URL scanner with input validation (handles missing `http(s)://`,
  empty input, malformed URLs)
- Machine-learning based classification (Random Forest), not simple
  keyword matching
- Confidence percentage for each prediction
- Scan history stored in SQLite, with a "Clear History" option
- Dashboard with total / safe / phishing counts and recent scans
- Clean, responsive, dark cybersecurity-themed UI
- Friendly error handling (no raw Python errors shown to the user)

## 3. Technology Stack

| Layer          | Technology                          |
|----------------|--------------------------------------|
| Backend        | Python, Flask                        |
| Machine Learning | scikit-learn (Random Forest), joblib |
| Frontend       | HTML5, CSS3, vanilla JavaScript      |
| Database       | SQLite                               |

## 4. Project Structure

```
phishing-url-detector/
│
├── app.py                    # Flask application (routes, prediction, DB)
├── training.py                # Trains the Random Forest model
├── feature_extractor.py       # Shared feature extraction (training + live use)
├── url_validator.py           # URL validation/normalization helpers
├── requirements.txt
├── README.md
│
├── dataset/
│   └── phishtank_data.csv     # Sample labeled URL dataset
│
├── model/
│   └── phishing_model.pkl     # Created after you run training.py
│
├── templates/
│   └── index.html             # Single template used for Home/History/About
│
├── static/
│   ├── css/
│   │   └── style.css
│   └── js/
│       └── script.js
│
└── database/
    └── logs.db                # Created automatically the first time you run app.py
```

## 5. Installation (Windows)

### 5.1 Create the project folder

Create a folder named `phishing-url-detector` and place all the
provided files inside it, matching the structure above.

### 5.2 Create a virtual environment

Open Command Prompt (or PowerShell) inside the `phishing-url-detector`
folder and run:

```bash
python -m venv venv
venv\Scripts\activate
```

You should see `(venv)` appear at the start of your terminal prompt.

### 5.3 Install dependencies

```bash
pip install -r requirements.txt
```

This installs Flask, scikit-learn, pandas, numpy, and joblib.

## 6. Dataset Setup

A small sample dataset is already included at
`dataset/phishtank_data.csv`, so you can train and test the app
immediately without finding your own data.

If you want to use your own dataset, replace that file with a CSV
that has at least two columns:

- A URL column, named `URL` or `url`
- A label column, named `Label` or `label`

Label values can be either `1` / `0`, or text values like
`phishing` / `safe` (also accepts `legitimate`, `good`, `bad`,
`benign`, `malicious`).

Example:

```csv
url,label
https://www.example.com,safe
http://secure-login-verify.example.net,phishing
```

The included sample dataset uses well-known real sites as "safe"
examples and clearly fictional, non-operational domains as
"phishing" examples — it does not link to any real malicious sites.

## 7. Train the Model

With your virtual environment activated, run:

```bash
python training.py
```

This will:

1. Load `dataset/phishtank_data.csv`
2. Clean the data and normalize labels
3. Extract features for every URL (using `feature_extractor.py`)
4. Split the data into training (80%) and testing (20%) sets
5. Train a Random Forest Classifier
6. Print accuracy, precision, recall, F1-score, and a confusion matrix
7. Save the trained model to `model/phishing_model.pkl`

You should see output in the terminal ending with something like:

```
Model saved to 'model/phishing_model.pkl'.
Done! You can now run 'python app.py' to start the web app.
```

## 8. Run the Flask Application

```bash
python app.py
```

The first time you run this, it will also create
`database/logs.db` automatically. Then open your browser and go to:

```
http://127.0.0.1:5000
```

## 9. How to Use the Scanner

1. On the homepage, find the **Scan a URL** box.
2. Type or paste a URL (e.g. `https://example.com` or just
   `example.com`).
3. Click **Scan URL**.
4. Wait for the short loading animation.
5. The result (SAFE or PHISHING) will appear along with a confidence
   percentage and a short explanation.
6. Click **Clear** to reset the form for another scan.
7. Visit the **History** page to see every past scan, or **About** to
   learn how the detection works.

## 10. Database Information

PhishGuard uses a single SQLite database file at
`database/logs.db`, with one table:

```sql
CREATE TABLE logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL,
    result TEXT NOT NULL,
    confidence REAL NOT NULL,
    timestamp TEXT NOT NULL
);
```

The database and table are created automatically the first time you
run `app.py` — you do not need to set anything up manually. You can
clear all logged scans from the History page.

## 11. Stopping and Restarting the Server

- To stop the server: go back to the terminal window running
  `python app.py` and press `Ctrl + C`.
- To start it again later: re-activate your virtual environment and
  run the app again:

```bash
venv\Scripts\activate
python app.py
```

You do **not** need to re-run `training.py` unless you want to
retrain the model (for example, after changing the dataset).

## 12. Testing Checklist

Use these cases to verify the app works correctly:

- [ ] Valid safe URL (e.g. `https://www.wikipedia.org`)
- [ ] Clearly suspicious test URL (e.g.
      `http://secure-login-verify-account.example-test.info`)
- [ ] Empty input submitted
- [ ] Invalid/garbage input (e.g. `not a url at all`)
- [ ] URL without HTTPS (e.g. `http://example.com`)
- [ ] Very long URL (100+ characters)
- [ ] URL containing special characters (`%`, `@`, `?`, `&`)
- [ ] Confirm each scan appears in `database/logs.db` (via the
      History page)
- [ ] History page displays past scans correctly
- [ ] "Clear History" empties the history table and dashboard counts
- [ ] Resize the browser window / view on a phone to check mobile
      responsiveness

**Note:** Do not test with real malicious URLs. Use harmless example
domains or the fictional patterns shown in the sample dataset.

## 13. Troubleshooting

**`ModuleNotFoundError` when running `app.py` or `training.py`**
Make sure your virtual environment is activated (`venv\Scripts\activate`)
and that you ran `pip install -r requirements.txt` inside it.

**"Model file not found" message on the homepage / scan fails**
You need to train the model first: run `python training.py` before
`python app.py`.

**Port 5000 already in use**
Close any other program using that port, or edit the last line of
`app.py` to use a different port, e.g. `app.run(debug=True, port=5050)`.

**Dataset errors when training**
Make sure `dataset/phishtank_data.csv` exists and has a URL column
(`URL`/`url`) and a label column (`Label`/`label`). Check the terminal
output — it lists the columns it found if something doesn't match.

**Database looks empty after scanning**
Make sure you're looking at `database/logs.db` in the same project
folder you're running `app.py` from; the app always creates/uses the
database relative to its own file location.

## 14. Limitations

- Trained on a small sample dataset by default — accuracy will
  improve significantly with a larger, more diverse dataset.
- Only analyzes the URL string itself; it does not visit the page,
  inspect page content, or check live blocklists.
- Not a substitute for a real anti-phishing or security product —
  built for learning and demonstration purposes.

## 15. Future Improvements

- Train on a larger, regularly updated phishing/legitimate URL
  dataset.
- Add optional page-content analysis (with appropriate safety
  sandboxing) in addition to URL-only features.
- Add user accounts so scan history is per-user.
- Add pagination and search/filter on the History page.
- Add automated unit tests for `feature_extractor.py` and
  `url_validator.py`.
- Deploy behind HTTPS with a production WSGI server (e.g. Gunicorn +
  Nginx) instead of the Flask development server.
