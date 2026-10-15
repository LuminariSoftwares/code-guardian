import os
import subprocess


def run_user_command():
    command = input("command: ")
    os.system(command)


def list_files():
    subprocess.run("ls -la", shell=True)


def calculate(expression):
    return eval(expression)
