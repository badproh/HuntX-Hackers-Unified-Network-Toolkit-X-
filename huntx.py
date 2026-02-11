#!/usr/bin/env python3
import sys
import socket
import os
import textwrap
import colorama
import time
import json
import threading
import subprocess
import abc
import uuid
import re
import shutil
import stat
import tarfile
import zipfile
import io
import xml.etree.ElementTree as ET
from typing import List, Dict, Any
from datetime import datetime, timezone 
from enum import Enum
from colorama import init
import random 
import string
import requests
import concurrent.futures 

# Initialize Colors
init(autoreset=True)
GREEN = '\033[92m'; YELLOW = '\033[93m'; RED = '\033[91m'; CYAN = '\033[96m'
BOLD = '\033[1m