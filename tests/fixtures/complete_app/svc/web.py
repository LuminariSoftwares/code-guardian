import os

from dotenv import load_dotenv
from flask import Flask

load_dotenv()
app = Flask(__name__)


@app.get("/")
def hello():
    return os.environ.get("SVC_GREETING", "hello")
