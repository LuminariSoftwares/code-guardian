"""The helper as it was before the move, still imported by app/main.py."""
import subprocess


def greet(name):
    return "hello " + name


def uptime():
    return subprocess.run("uptime", shell=True, capture_output=True, text=True).stdout
