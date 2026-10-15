import os

TOKEN_NAME = os.environ.get("BARE_TOKEN_NAME", "")


def main():
    return TOKEN_NAME
