import socket

import requests

UPLOAD_URL = "http://{host}:8080/upload"
DOCS_URL = "https://example.com/docs"
PEER = "100.64.0.5"


def upload(data, host=PEER):
    return requests.post(UPLOAD_URL.format(host=host), data=data, verify=False)


def serve():
    server = socket.socket()
    server.bind(("0.0.0.0", 8080))
    server.listen()
    return server
