# Modules
import argparse

# Use argparse so people can enter their passwords from the terminal
parser = argparse.ArgumentParser()
parser.add_argument("password")
args = parser.parse_args()

def check_password_strength(password):
    password = password.lower()
    print("Checking password strength...")
    print(checkRepeatedCharacters(password))
    print(checkCommonWords(password))
    print(checkYears(password))
    print(keyboardPatterns(password))

# Function to check if the password contains any common words
def checkCommonWords(password):
    # Opens the common-words.txt file
    with open ("common-words.txt", "r") as f:
        # Reads the common_words.txt file and splits it into a list of words
        common_words = f.read().splitlines()
        # Loops through each word in the common_words list
        for word in common_words:
            # Checks if the word is in the password and returns an appropriate response 
            if word in password:
                return "Weak password: contains common word '{}'".format(word)
    return "Strong password: no common words found."

# Function to check if the password contains any sequences of 4 or more consecutive years
def checkYears(password):
    # Define a list called groups to store the groups of 4 characters
    groups = []
    i = 0
    currentPosition = 0
    # Loop through the password providing i is less than the length of the password
    for ch in password:
        string = ""
        for i in range(4):
            if currentPosition + i < len(password):
                string += password[currentPosition + i]
                i += 1

        currentPosition += 1
        groups.append(string)



    for group in groups:
        if group.isdigit() and 1900 <= int(group) <= 2024:
            return "Weak password: contains year '{}'".format(group)
    return "Strong password: no years found."

def keyboardPatterns(password):
    # Define a list of common keyboard patterns
    patterns = ["qwerty", "asdfgh", "zxcvbn", "123456", "password"]
    '''for pattern in patterns:
            newPattern = ""
            for char in pattern:
                if ord(char) + 1 > 126:
                    char = ord(char) + 1 - 95
                    char = chr(char)
                    newPattern += char
                else:
                    char = ord(char) + 1
                    char = chr(char)
                    newPattern += char
            patterns.append(newPattern)

    print(patterns)'''

    for pattern in patterns:
        if pattern in password or pattern[::-1] in password:
            return "Weak password: contains keyboard pattern '{}'".format(pattern)
    return "Strong password: no keyboard patterns found."

def checkRepeatedCharacters(password):
    # Check for repeated characters 
    for ch in password:
        if password.count(ch) > 2:
            return "Weak password: contains repeated character '{}'".format(ch)
    return "Strong password: no repeated characters found."

check_password_strength(args.password)