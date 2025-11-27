# Phishing-Classifier
An end-to-end phishing URL detection project with a Flask web UI, training pipeline, batch prediction support, and MongoDB-backed feedback/labeling. The repository includes data ingestion, validation, feature extraction, model training, and prediction components used to build and serve a binary classifier that identifies phishing vs legitimate URLs.

### Demo & Docker
- **Demo video:** https://drive.google.com/file/d/11qGm3aQ1awQLwnqi8drXofbr1-8uDGt7/view?pli=1
- **Docker image:** https://hub.docker.com/r/aditya2913/phishing-classifier/

---

**Quick links:**
- **App entrypoint:** `app.py`
- **Training pipeline:** `src/pipeline/train_pipeline.py`
- **Prediction pipeline:** `src/pipeline/predict_pipeline.py`
- **Trained model path:** `trained_model/model.pkl`

---

**Table of contents**
- **Project Overview** — what this repo does
- **Tech Stack & Dependencies** — key libraries and versions
- **Repository Structure** — important files and folders
- **Local Setup** — environment, install, run
- **Usage** — web UI, API endpoints, batch prediction
- **Training & Model Artifacts** — how to train and where outputs are stored
- **Database (MongoDB)** — collections used for feedback and dataset growth
- **Docker & Deployment** — notes for containerized usage
- **Contributing & Next Steps** — how to help

**Project Overview**
- **Purpose:** Detect phishing URLs using engineered features extracted from a URL and a binary classifier. The app provides a web UI to classify individual URLs, an admin interface to verify reported classifications, and a batch prediction endpoint for CSV uploads.
- **Key features:** URL feature extraction, training pipeline (ingest → validate → transform → train), prediction endpoint, MongoDB-backed feedback loop to grow labeled dataset.

**Tech Stack & Dependencies**
- **Language:** Python 3.8+ (recommend 3.9–3.11)
- **Web server:** Flask (`app.py` uses Flask and runs on port `8080` by default)
- **ML libraries:** `scikit-learn`, `xgboost`, `tensorflow` (see `requirements.txt` for full list)
- **Database:** MongoDB (Atlas or local) for storing classified/reported URLs and dataset entries

**Repository Structure (high level)**
- **`app.py`**: Flask application and endpoints (`/`, `/train`, `/predict`, `/url_classifier`, admin routes)
- **`src/`**: application source code
	- **`src/pipeline/`**: `train_pipeline.py`, `predict_pipeline.py`
	- **`src/components/`**: ingestion, validation, transformation, trainer components
	- **`src/utils/`**: helpers and feature extraction (`extract_features.py`)
	- **`src/constant/`**: constants such as `TARGET_COLUMN`, admin env names
- **`trained_model/`**: trained model file(s) (e.g. `model.pkl`)
- **`artifacts/`**: pipeline run artifacts (timestamps)
- **`prediction_artifacts/`**, **`predictions/`**: temporary upload and prediction outputs
- **`templates/`** and **`static/`**: Flask templates and static frontend assets

**Environment & Prerequisites**
- **Install Python** (recommended 3.9+). Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

- **Install dependencies**:

```bash
pip install -r requirements.txt
```

- **Environment variables** (recommended to set in a `.env` file or your shell):
	- `SessionSecretKey` — secret key used by Flask sessions
	- `MONGODB_URL` — MongoDB connection string (e.g. Atlas URI)
	- `AdminID` and `AdminPassword` — credentials for admin actions (used via `src/constant`)
	- (Optional) AWS-related env vars if you enable S3 model download

Example `.env` (not included in repo):

```env
SessionSecretKey=change_me_securely
MONGODB_URL=mongodb+srv://user:pass@cluster.example.mongodb.net/?retryWrites=true&w=majority
AdminID=admin
AdminPassword=secret
```

**Run the app (local)**
- Start the Flask app (development):

```bash
export SessionSecretKey='your_secret'
export MONGODB_URL='your_mongodb_uri'
export AdminID='admin'
export AdminPassword='password'
python app.py
```

- Open `http://localhost:8080` in a browser. The Flask server uses `host=0.0.0.0` and `port=8080` by default.

**Usage: Web UI & API**
- **Home & URL classifier UI:** `GET /` and `GET /url_classifier` — open in browser and submit a single URL for classification.
- **Batch prediction (CSV):** `POST /predict` with multipart form `file=@your_file.csv` — returns the CSV of predictions as a downloadable file.

Example `curl` to upload a CSV and download the result:

```bash
curl -F "file=@/path/to/urls.csv" http://localhost:8080/predict -o predicted_file.csv
```

- **Admin & training**:
	- `POST /admin_login` — JSON {"adminID": "...", "adminPassword": "..."} to sign in (session-based)
	- `GET /train` — triggers training pipeline from the Flask route (requires admin session). Training will run `TrainingPipeline().run_pipeline()` which executes ingestion → validation → transformation → trainer.

**Training (programmatic)**
- You can also run training directly from Python (useful for dev/CI):

```bash
python -c "from src.pipeline.train_pipeline import TrainingPipeline; TrainingPipeline().run_pipeline()"
```

**Model & Artifacts**
- **Trained model:** `trained_model/model.pkl` (loaded by `app.py` on startup)
- **Preprocessor:** saved path returned by the data transformation step; look in `artifacts/<timestamp>/` for transformer and intermediate datasets
- **Predictions:** batch outputs saved to `predictions/predicted_file.csv` by `PredictionPipeline`

**Data & Datasets**
- Example and notebook datasets are in:
	- `Phishing URL dataset/` (CSV sources)
	- `notebook implementation/` (Jupyter notebook used during development)
	- Validated dataset from pipeline: `artifacts/<timestamp>/data_validation/validated/dataset.csv`

**MongoDB Usage & Collections**
- The app uses MongoDB to store and manage classification and feedback data. Collections used include:
	- `classified_urls`: URLs automatically classified by the model (and their features)
	- `reported_urls`: URLs reported by users as incorrect predictions (awaiting admin verification)
	- `dataset`: manually verified entries moved to the training dataset by admin actions

Admin endpoints allow verifying reported URLs and moving classified entries into the dataset collection (see `app.py` for logic and collection names).

**Docker & Deployment**
- A `Dockerfile` is included for containerized deployment. The image is available at the Docker Hub link above. Typical steps:

```bash
# build
docker build -t phishing-classifier:local .

# run (make sure to pass envs securely)
docker run -e SessionSecretKey='...' -e MONGODB_URL='...' -p 8080:8080 phishing-classifier:local
```

**Security & Production Notes**
- Do not hardcode secrets in code. Use environment variables or a secrets manager.
- Running training from a web endpoint (`/train`) is convenient for demo but not recommended for production — prefer running training in a separate worker or CI job.
- Validate and sanitize any uploaded data used for prediction.

**Development & Contributing**
- **Run training locally**: see `src/pipeline/train_pipeline.py` for pipeline flow (ingest → validate → transform → train)
- **Add tests:** there are no tests included — consider adding unit tests for `src/utils/` and `src/components/` pieces
- **Style & formatting:** use `black`/`flake8` if desired; keep changes minimal and focused

**Troubleshooting**
- If `trained_model/model.pkl` is missing the app starts but `model` will be `None` and classification endpoints depending on it will fail; train a model first or provide a model file.
- Check `MONGODB_URL` connectivity for admin features to work (reporting, moving to dataset).
