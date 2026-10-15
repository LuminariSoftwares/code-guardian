import pickle

import yaml


def load_state(path):
    with open(path, "rb") as fh:
        return pickle.load(fh)


def load_config(text):
    return yaml.load(text)


def save_report(text):
    with open("/tmp/risky-report.txt", "w") as fh:
        fh.write(text)
