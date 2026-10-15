import requests

API_URL = "https://example.com/api"


def fetch(path=""):
    response = requests.get(API_URL + path, timeout=10)
    response.raise_for_status()
    return response.text
