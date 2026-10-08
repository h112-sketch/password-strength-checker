# Modules
import argparse

# Use argparse so people can enter their passwords from the terminal
parser = argparse.ArgumentParser()
parser.add_argument("password")
args = parser.parse_args()