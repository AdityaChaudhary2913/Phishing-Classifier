import sys
import os
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.impute import SimpleImputer
from imblearn.over_sampling import RandomOverSampler
from src.constant import *
from src.exception import CustomException
from src.logger import logging
from src.utils.main_utils import MainUtils
from dataclasses import dataclass

@dataclass
class DataTransformationConfig:
    data_transformation_dir = os.path.join(artifact_folder, 'data_transformation')
    transformed_train_file_path = os.path.join(data_transformation_dir, 'train.npy')
    transformed_test_file_path = os.path.join(data_transformation_dir, 'test.npy')
    transformed_object_file_path = os.path.join(data_transformation_dir, 'preprocessing.pkl')
    
class DataTransformation:
  def __init__(self, valid_data_dir):
    self.valid_data_dir = valid_data_dir
    self.data_transformation_config = DataTransformationConfig()
    self.utils = MainUtils()
  
  # This method reads all the validated raw data from the valid_data_dir and returns a pandas DataFrame containing the merged data.
  @staticmethod
  def get_merged_batch_data(valid_data_dir: str) -> pd.DataFrame:
    try:
      raw_files = os.listdir(valid_data_dir)
      csv_data = list()
      for filename in raw_files:
        data = pd.read_csv(os.path.join(valid_data_dir, filename))
        csv_data.append(data)
      merged_data = pd.concat(csv_data)
      return merged_data
    except Exception as e:
      raise CustomException(e, sys) from e
  
  def initiate_data_transformation(self):
    logging.info("Entered initiate_data_transformation method of DataTransformation class")
    try:
      dataframe = self.get_merged_batch_data(valid_data_dir=self.valid_data_dir)
      dataframe = self.utils.remove_unwanted_spaces(dataframe)
      dataframe.replace('?', np.NaN, inplace=True)  # replacing '?' with NaN values for imputation
      
      X = dataframe.drop(columns=TARGET_COLUMN)
      y = np.where(dataframe[TARGET_COLUMN] == -1, 0, 1)
      
      sampler = RandomOverSampler()         
      x_sampled, y_sampled = sampler.fit_resample(X, y)
      
      X_train, X_test, y_train, y_test = train_test_split(x_sampled, y_sampled, test_size=0.2)
      
      preprocessor = SimpleImputer(strategy='most_frequent')
      
      x_train_scaled = preprocessor.fit_transform(X_train)
      x_test_scaled = preprocessor.transform(X_test)
      
      preprocessor_path = self.data_transformation_config.transformed_object_file_path
      os.makedirs(os.path.dirname(preprocessor_path), exist_ok=True)
      self.utils.save_object(filePath=preprocessor_path, obj=preprocessor) 
      
      return x_train_scaled, y_train, x_test_scaled, y_test, preprocessor_path     
    except Exception as e:
      raise CustomException(e, sys) from e