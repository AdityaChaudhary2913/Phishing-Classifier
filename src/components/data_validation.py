import sys
from typing import List
import pandas as pd
import re
import os
import shutil
import json

from env.Lib.pathlib import Path
from src.constant import *
from src.exception import CustomException
from src.logger import logging
from src.utils.main_utils import MainUtils
from dataclasses import dataclass

LENGTH_OF_DATE_STAMP_IN_FILE = 8
LENGTH_OF_TIME_STAMP_IN_FILE = 6
NUMBER_OF_COLUMNS = 11