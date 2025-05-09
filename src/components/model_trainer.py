import sys
import os
import pandas as pd
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.metrics import accuracy_score
from sklearn.naive_bayes import GaussianNB
from sklearn.compose import ColumnTransformer
from xgboost import XGBClassifier
from sklearn.model_selection import GridSearchCV
from tensorflow.keras.models import Sequential
import tensorflow.keras as tf
from tensorflow.keras.layers import Dense, Input
# from tensorflow.keras.layers import Embedding, SimpleRNN, LSTM, GRU
from scikeras.wrappers import KerasClassifier
from src.constant import *
from src.exception import CustomException
from src.logger import logging
from src.utils.main_utils import MainUtils

from dataclasses import dataclass

# # RNN Model
# def create_rnn_model(input_shape):
#     model = Sequential()
#     model.add(Embedding(input_dim=1000, output_dim=64, input_length=input_shape))  # Adjust `input_dim` as needed
#     model.add(SimpleRNN(64, activation='relu'))
#     model.add(Dense(1, activation='sigmoid'))
#     model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
#     return model

# # LSTM Model
# def create_lstm_model(input_shape):
#     model = Sequential()
#     model.add(Embedding(input_dim=1000, output_dim=64, input_length=input_shape))
#     model.add(LSTM(64, activation='relu'))
#     model.add(Dense(1, activation='sigmoid'))
#     model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
#     return model

# # GRU Model
# def create_gru_model(input_shape):
#     model = Sequential()
#     model.add(Embedding(input_dim=1000, output_dim=64, input_length=input_shape))
#     model.add(GRU(64, activation='relu'))
#     model.add(Dense(1, activation='sigmoid'))
#     model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
#     return model

def create_ann_model():
    model = Sequential()
    model.add(Input(shape=(30,)))
    model.add(Dense(128, activation='relu'))
    model.add(Dense(64, activation='relu'))
    model.add(Dense(32, activation='relu'))
    model.add(Dense(1, activation='sigmoid'))  # Binary classification
    model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
    return model

@dataclass
class ModelTrainerConfig:
    model_trainer_dir = os.path.join(artifact_folder, 'model_trainer')
    trained_model_path = os.path.join(model_trainer_dir, 'trained_model', "model.pkl")
    expected_accuracy = 0.75
    model_config_file_path = os.path.join('config', 'model.yaml')

class VisibilityModel:
    def __init__(self, preprocessing_object: ColumnTransformer, trained_model_object):
        self.preprocessing_object = preprocessing_object
        self.trained_model_object = trained_model_object

    def predict(self, X: pd.DataFrame) -> pd.DataFrame:
        logging.info("Entered predict method of VisibilityModel class")
        try:
            logging.info("Using the trained model to get predictions")
            transformed_feature = self.preprocessing_object.transform(X)
            logging.info("Used the trained model to get predictions")
            return self.trained_model_object.predict(transformed_feature)
        except Exception as e:
            raise CustomException(e, sys) from e

    def __repr__(self):
        return f"{type(self.trained_model_object).__name__}()"

    def __str__(self):
        return f"{type(self.trained_model_object).__name__}()"
    
class ModelTrainer:
    def __init__(self):
        self.model_trainer_config = ModelTrainerConfig()
        self.utils = MainUtils()
        self.models = {
            "GaussianNB": GaussianNB(),
            "XGBClassifier": XGBClassifier(objective='binary:logistic'),
            "LogisticRegression": LogisticRegression(),
            "RandomForestClassifier": RandomForestClassifier(),
            "SVC": SVC(),
            "ANN": KerasClassifier(model=create_ann_model(), epochs=500, batch_size=32, callbacks=[tf.callbacks.EarlyStopping(monitor='loss', patience=5)]),
            # "RNN": KerasClassifier(model=lambda: create_rnn_model(input_shape), epochs=50, batch_size=32),
            # "LSTM": KerasClassifier(model=lambda: create_lstm_model(input_shape), epochs=50, batch_size=32),
            # "GRU": KerasClassifier(model=lambda: create_gru_model(input_shape), epochs=50, batch_size=32)
        }

    def evaluate_models(self, X_train, X_test, y_train, y_test, models):
        try:
            report = {}
            for i in range(len(list(models))):
                model = list(models.values())[i]
                model_name = list(models.keys())[i]
                
                model.fit(X_train, y_train)  # Train model
                
                y_train_pred = model.predict(X_train)
                y_test_pred = model.predict(X_test)
                
                train_model_score = accuracy_score(y_train, y_train_pred)*100
                test_model_score = accuracy_score(y_test, y_test_pred)*100
                
                print(f"\nTesting Accuracy of {model_name}: {test_model_score:.2f}%")
                print(f"Training Accuracy of {model_name}: {train_model_score:.2f}%\n")
                
                report[model_name] = test_model_score
            return report
        except Exception as e:
            raise CustomException(e, sys)
    
    def get_best_model(self, x_train: np.array, y_train: np.array, x_test: np.array, y_test: np.array):
        try:
            model_report: dict = self.evaluate_models(x_train, x_test, y_train, y_test, self.models)
            print(model_report)
            best_model_score = max(sorted(model_report.values())) * 100
            best_model_name = list(model_report.keys())[list(model_report.values()).index(best_model_score)]
            best_model_object = self.models[best_model_name]
            print(f"\nBest Model: {best_model_name} with Accuracy: {best_model_score:.2f}%")
            return best_model_name, best_model_object, best_model_score
        except Exception as e:
            raise CustomException(e, sys)

    def finetune_best_model(self, best_model_object: object, best_model_name, X_train, y_train) -> object:
        try:
            model_param_grid = self.utils.read_yaml_file(self.model_trainer_config.model_config_file_path)["model_selection"]["model"][best_model_name]["search_param_grid"]
            grid_search = GridSearchCV(best_model_object, param_grid=model_param_grid, cv=5, n_jobs=-1, verbose=1)
            grid_search.fit(X_train, y_train)
            best_params = grid_search.best_params_
            print("best params are:", best_params)
            finetuned_model = best_model_object.set_params(**best_params)
            return finetuned_model
        except Exception as e:
            raise CustomException(e, sys)
        
    def initiate_model_trainer(self, x_train, y_train, x_test, y_test, preprocessor_path):
        try:
            logging.info(f"Splitting training and testing input and target feature")
            logging.info(f"Extracting model config file path")
            preprocessor = self.utils.load_object(file_path=preprocessor_path)
            logging.info(f"Extracting model config file path")
            model_report: dict = self.evaluate_models(X_train=x_train, y_train=y_train, X_test=x_test, y_test=y_test, models=self.models)
            best_model_score = max(sorted(model_report.values()))
            best_model_name = list(model_report.keys())[list(model_report.values()).index(best_model_score)]
            best_model = self.models[best_model_name]
            best_model = self.finetune_best_model(best_model_name=best_model_name, best_model_object=best_model, X_train=x_train, y_train=y_train)
            best_model.fit(x_train, y_train)
            y_pred = best_model.predict(x_test)
            best_model_score = accuracy_score(y_test, y_pred) * 100
            print(f"\nFinal Best Model: {best_model_name} with Accuracy after fine-tuning: {best_model_score:.2f}%")
            if best_model_score < 0.5:
                raise Exception("No best model found with an accuracy greater than the threshold 0.6")
            logging.info(f"Best found model on both training and testing dataset")
            custom_model = VisibilityModel(preprocessing_object=preprocessor, trained_model_object=best_model)
            logging.info(f"Saving model at path: {self.model_trainer_config.trained_model_path}")
            os.makedirs(os.path.dirname(self.model_trainer_config.trained_model_path), exist_ok=True)
            self.utils.save_object(filePath=self.model_trainer_config.trained_model_path, obj=custom_model)
            # self.utils.upload_file(fromFileName=self.model_trainer_config.trained_model_path, toFileName="model.pkl", bucketName=AWS_S3_BUCKET_NAME)
            return best_model_score
        except Exception as e:
            raise CustomException(e, sys)