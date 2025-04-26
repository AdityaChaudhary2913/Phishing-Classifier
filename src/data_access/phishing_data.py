import sys
from typing import Iterator, List, Tuple
# from database_connect.databases import mongodb as mongo
from pymongo import MongoClient
import certifi
import numpy as np
import pandas as pd
from src.constant import *
from src.exception import CustomException
import os

class PhishingData:
  def __init__(self, db_name: str):
    try:
      self.database_name = db_name
      self.mongo_url = os.getenv("MONGODB_URL")
      ca_file = certifi.where() # export SSL_CERT_FILE=$(python -c "import certifi; print(certifi.where())")
      self.client = MongoClient(self.mongo_url, tls=True, tlsCAFile=ca_file)
      self.db = self.client[self.database_name]
    except Exception as e:
      raise CustomException(e, sys) from e
  
  def get_collection_names(self) -> List:
    # mongo_db_client = MongoClient(self.mongo_url)
    collection_names = self.db.list_collection_names()
    return collection_names
  
  def get_collection_data(self, collection_name: str) -> pd.DataFrame:
    try:
      # mongo_connection = mongo.MongoIO(client_url=self.mongo_url, database_name=self.database_name, collection_name=collection_name)
      # df = mongo_connection.find()
      data = self.db[collection_name].find()
      df = pd.DataFrame(list(data))
      if "_id" in df.columns:
          df = df.drop(columns=["_id"])
      df = df.replace({"na": np.nan})
      return df
    except Exception as e:
        raise CustomException(e,sys) from e
  
  def export_collections_as_dataframe(self) -> Iterator[Tuple[str, pd.DataFrame]]:
    try:
        collections = self.get_collection_names()
        for collection_name in collections:
            df = self.get_collection_data(collection_name=collection_name)
            yield collection_name, df
    except Exception as e:
        raise CustomException(e,sys) from e