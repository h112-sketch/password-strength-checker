
# Modules
import argparse
import datetime
import math

def check_password_strength(original_password):
    guesses = calculate_guesses(original_password)
    print(guesses)
    password = original_password.lower()
    print("Checking password strength...")
    check_common_words_result = check_common_words(password)

    check_years_result = check_years(password)
    keyboard_patterns_result = keyboard_patterns(password)
    check_repeated_characters_result = check_repeated_characters(password)

def calculate_guesses(password):
    # Calculate the number of guesses based on the character set size and password length
    character_set_size = calculate_character_set_size(password)
    if character_set_size == 0:
        return 0
    password_length = len(password)
    guesses = password_length * math.log2(character_set_size)
    return guesses

def calculate_character_set_size(password):
    # Calculate the character set size based on the types of characters in the password
    character_set_size = 0
    if any(c.islower() for c in password):
        character_set_size += 26
    if any(c.isupper() for c in password):
        character_set_size += 26
    if any(c.isdigit() for c in password):
        character_set_size += 10
    if any(c in "!@#$%^&*()-_=+[{]}\|;:'\",<.>/?`~" for c in password):
        character_set_size += 33
    return character_set_size   

# Function to check if the password contains any common words
def check_common_words(password):
    # Opens the common-words.txt file
    with open ("common-words.txt", "r") as f:
        # Reads the common_words.txt file and splits it into a list of words
        common_words = f.read().splitlines()
        # Loops through each word in the common_words list
        number_of_hits = 0
        hits = []
        for word in common_words:
            # Checks if the word is in the password and returns an appropriate response
            if word in password:
                number_of_hits += 1
                hits.append(word)
    if number_of_hits > 0:
        return {"flagged": True, "type": "common_words", "result": number_of_hits, "message": f"Password contains common words: {number_of_hits} ({', '.join(hits)})"}
    return {"flagged": False, "type": "common_words", "message": "Password does not contain any common words."}

# Function to check if the password contains any sequences of 4 or more consecutive years
def check_years(password):
    # Define a list called groups to store the groups of 4 characters
    groups = []
    # Define a variable to keep track of the current position in the password
    current_position = 0
    number_of_hits = 0
    hits = []
    # Loop through the password
    for ch in password:
        # Create a string variable to store the group of 4 characters
        string = ""
        # Loop through the next 4 characters in the password
        for i in range(4):
            # Check if the current position plus i is less than the length of the password
            if current_position + i < len(password):
                string += password[current_position + i]
                
        current_position += 1
        groups.append(string)

    # Loop through the groups list and check if any of the groups are a year between 1900 and the current year
    for group in groups:
        # Check if the group is a digit and if it is between 1900 and the current year
        if group.isdigit() and 1900 <= int(group) <= datetime.datetime.now().year:
            number_of_hits += 1
            hits.append(group)
    if number_of_hits > 0:
        return {"flagged": True, "type": "years", "result": number_of_hits, "message": f"Password contains years: {number_of_hits} ({', '.join(hits)})"}
    return {"flagged": False, "type": "years", "message": "Password does not contain any years."}

def keyboard_patterns(password):
    # Define a list of common keyboard patterns
    keyboard = ["qwerty", "asdfghjkl", "qwertyuiop", "zxcvbnm", "1234567890", "!@#$%^&*()"]
    chunks = []
    # Loop through the password and create chunks of 4 characters
    for chunk in range(len(password) - 3):
        # Create a substring of 4 characters from the password
        substring = password[chunk:chunk + 4]
        # Append the substring to the chunks list
        chunks.append(substring)
    # Loop through the keyboard patterns and check if any of the chunks are in the patterns
    numberOfHits = 0
    hits = []
    for pattern in keyboard:
        #  Loop through the chunks and check if any of the chunks are in the pattern or if the reverse of the chunk is in the pattern
        for chunk in chunks:
            # Check if the chunk is in the pattern or if the reverse of the chunk is in the pattern
            if chunk in pattern or chunk[::-1] in pattern:
                hits.append(chunk)
                numberOfHits += 1
    if numberOfHits > 0:
        return {"flagged": True, "type": "keyboard_patterns", "result": numberOfHits, "message": f"Password contains keyboard patterns: {numberOfHits} ({', '.join(hits)})"}
    return {"flagged": False, "type": "keyboard_patterns", "message": "Password does not contain keyboard patterns."}

def check_repeated_characters(password):
    # Check for repeated characters
    number_of_hits = 0
    hits = []
    for i in range(len(password) - 2):
        # Check if the current character is the same as the next two characters
        if password[i] == password[i+1] and password[i] == password[i+2]:
            # If a repeated character is found, return a dictionary with the flagged status, type, character, and message
            ch = password[i]
            number_of_hits += 1
            hits.append(ch)
    if number_of_hits > 0:
        return {"flagged": True, "type": "repeated_characters", "result": number_of_hits, "message": f"Password contains repeated characters: {number_of_hits} ({', '.join(hits)})"}
    return {"flagged": False, "type": "repeated_characters", "message": "Password does not contain repeated characters."}

if __name__ == "__main__":
    # Use argparse so people can enter their passwords from the terminal
    parser = argparse.ArgumentParser()
    parser.add_argument("password")
    args = parser.parse_args()

    check_password_strength(args.password)
