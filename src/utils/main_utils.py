import sys
from typing import Dict, Tuple
import os

import numpy as np
import pandas as pd
import pickle
import yaml
import boto3

from src.constant import *
from src.exception import CustomException
from src.logger import logging

# This class contains utility functions in data handling.
class MainUtils:
  def __init__(self):
    pass
  
  # .yaml file is needed for deploying model on production level
  def read_yaml_file(self, fileName: str) -> dict:
    try:
      with open(fileName, 'rb') as file:
        return yaml.safe_load(file)
    except Exception as e:
      logging.error(f"Error while reading yaml file: {e}")
      raise CustomException(e, sys) from e
  
  def read_schema_config_file(self) -> dict:
    try:
      schema_config = self.read_yaml_file(os.path.join("config", "training_schema.yaml"))
      return schema_config
    except Exception as e:
      raise CustomException(e, sys) from e
  
  @staticmethod
  def save_object(filePath: str, obj: object) -> None:
    logging.info("Entered the save_object method of MainUtils class")
    try:
      with open(filePath, 'wb') as file:
        pickle.dump(obj, file)
      logging.info("Exited the save_object method of MainUtils class")
    except Exception as e:
      logging.error(f"Error while saving object: {e}")
      raise CustomException(e, sys) from e
    
  @staticmethod
  def upload_file(fromFileName, toFileName, bucketName):
    try:
      s3Res = boto3.resource('s3')
      s3Res.meta.client.upload_file(fromFileName, bucketName, toFileName)
    except Exception as e:
      raise CustomException(e, sys) from e
    
  @staticmethod
  def download_model(bucketName, fromFileName, toFileName):
    try:
      s3Res = boto3.client('s3')
      s3Res.download_file(bucketName, fromFileName, toFileName)
      return toFileName
    except Exception as e:
      raise CustomException(e, sys) from e
    
  @staticmethod
  def remove_unwanted_spaces(data: pd.DataFrame) -> pd.DataFrame:
    try:
      df_without_spaces = data.apply(
        lambda x: x.str.strip() if x.dtype == "object" else x)  # drop the labels specified in the columns
      logging.info('Unwanted spaces removal Successful.\nExited the remove_unwanted_spaces method of the Preprocessor class')
      return df_without_spaces
    except Exception as e:
      raise CustomException(e, sys)
        
  @staticmethod
  def identify_feature_types(dataframe: pd.DataFrame):
    data_types = dataframe.dtypes
    categorical_features = []
    continuous_features = []
    discrete_features = []
      
    for column, dtype in dict(data_types).items():
      unique_values = dataframe[column].nunique()

      if dtype == 'object' or unique_values < 10:  # Consider features with less than 10 unique values as categorical
        categorical_features.append(column)
      elif dtype in [np.int64, np.float64]:  # Consider features with numeric data types as continuous or discrete
        if unique_values > 20:  # Consider features with more than 20 unique values as continuous
          continuous_features.append(column)
        else:
          discrete_features.append(column)
      else: 
        pass # Handle other data types if needed
    return categorical_features, continuous_features, discrete_features