from datetime import datetime
import os

AWS_S3_BUCKET_NAME = "Data Science Projects"
MONGO_DATABASE_NAME = "phishing"

TARGET_COLUMN = "Result"

MODEL_FILE_NAME = "phishing_classifier"
MODEL_FILE_EXTENSION = ".pkl"

ADMIN_ID = os.getenv("AdminID")
ADMIN_PASSWORD = os.getenv("AdminPassword")

artifact_folder_name = datetime.now().strftime('%m_%d_%Y_%H_%M_%S')
artifact_folder = os.path.join("artifacts", artifact_folder_name)