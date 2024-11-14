import sys
import os
import numpy as np
import pandas as pd
from zipfile import Path
from src.constant import *
from src.exception import CustomException
from src.logger import logging

from src.data_access.phishing_data import PhishingData
from src.utils.main_utils import MainUtils
from dataclasses import dataclass

@dataclass
class DataIngestionConfig:
  dataIngestionDir: str = os.path.join(artifact_folder, "data_ingestion")
  
class DataIngestion:
  def __init__(self):
    self.data_ingestion_config = DataIngestionConfig()
    self.utils = MainUtils()
  
  def export_data_into_raw_data_dir(self) -> pd.DataFrame:
    try:
      logging.info(f"Exporting data from mongodb")
      raw_batch_files_path = self.data_ingestion_config.dataIngestionDir
      os.makedirs(raw_batch_files_path, exist_ok=True)
      incoming_data = PhishingData(db_name=MONGO_DATABASE_NAME)
      logging.info(f"Saving exported data into feature store file path: {raw_batch_files_path}")
      for collection_name, dataset in incoming_data.export_collections_as_dataframe():
        if collection_name == 'dataset':
          logging.info(f"Shape of {collection_name}: {dataset.shape}")
          feature_store_file_path = os.path.join(raw_batch_files_path, collection_name + '.csv')
          print(f"feature_store_file_path-----{feature_store_file_path}")
          dataset.to_csv(feature_store_file_path, index=False)
    except Exception as e:
      raise CustomException(e, sys) from e
  
  def initiate_data_ingestion(self) -> Path:
    logging.info("Entered initiate_data_ingestion method of Data_Ingestion class")
    try:
      self.export_data_into_raw_data_dir()
      logging.info("Got the data from mongodb")
      logging.info("Exited initiate_data_ingestion method of Data_Ingestion class")
      return self.data_ingestion_config.dataIngestionDir
    except Exception as e:
      raise CustomException(e, sys) from e