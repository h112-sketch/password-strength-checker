
# Modules
import argparse
import datetime
import math

costs = {
    "years" : 7,
    "common_words" : 13.3,
    "keyboard_patterns" : 6,
    "repeated_characters" : 6.6
}

attacker_speeds = {
    "online" : 10, # (guesses per second)
    "offline" : 10 ** 10 # (guesses per second)
}

test_passwords = [
    "password",
    "monkey1998",
    "correcthorsebatterystaple",
    "x7#Kq!9vLm2$"
]


def check_password_strength(original_password):
    entropy = calculate_entropy_bits(original_password)
    all_Matches = []
    password = original_password.lower()

    check_common_words_result = check_common_words(password)
    check_years_result = check_years(password)
    keyboard_patterns_result = keyboard_patterns(password)
    check_repeated_characters_result = check_repeated_characters(password)


    for result in [check_common_words_result, check_years_result, keyboard_patterns_result, check_repeated_characters_result]:
        all_Matches.extend(result["matches"])
        for match in result["matches"]:
            match["type"] = result["type"]

    all_Matches.sort(reverse=True, key=lambda x: x["end"] - x["start"])

    claimed_positions = set()
    totalCost = 0
    for match in all_Matches:
        if any(pos in claimed_positions for pos in range(match["start"], match["end"])):
            continue
        claimed_positions.update(range(match["start"], match["end"]))
        totalCost += costs[match["type"]]


    leftOverString = ""
    for i in range(len(original_password)):
        if i not in claimed_positions:
            leftOverString += original_password[i]

    leftover_bits = calculate_entropy_bits(leftOverString)
    final_bits = totalCost + leftover_bits

    guesses = 2 ** final_bits
    onlineAttackerSpeed = attacker_speeds["online"] # (guesses per second)
    offlineAttackerSpeed = attacker_speeds["offline"] # (guesses per second)

    onlineCrackTime = guesses / onlineAttackerSpeed
    offlineCrackTime = guesses / offlineAttackerSpeed



        
    print("Leftover string:", leftOverString)
    print("Naive entropy (whole password as random):", round(entropy, 1), "bits")
    print("Pattern cost:", totalCost, "bits")
    print("Leftover bits:", round(leftover_bits, 1), "bits")
    print("Final estimate:", round(final_bits, 1), "bits")
    print("Estimated guesses:", round(guesses, 1))


    print("Estimated online crack time:", turn_to_readable_time(onlineCrackTime))
    print("Estimated offline crack time:", turn_to_readable_time(offlineCrackTime))

    score, strength = score_password_strength(final_bits)
    print(f"Password strength score: {score} ({strength})")



def score_password_strength(final_bits):
    # Score the password strength based on the final bits of entropy
    if final_bits < 10:
        return 0, "Very Weak"
    elif final_bits < 20:
        return 1, "Weak"
    elif final_bits < 27:
        return 2, "Fair"
    elif final_bits < 33:
        return 3, "Good"
    else:
        return 4, "Strong"

def turn_to_readable_time(seconds):
    # Convert seconds to a human-readable format
    MINUTE = 60
    HOUR = 60 * MINUTE
    DAY = 24 * HOUR
    YEAR = 365 * DAY
    AGE_OF_UNIVERSE = 13.8e9 * YEAR  # about 13.8 billion years

    if seconds < 1:
        return "less than a second"
    elif seconds < MINUTE:
        return f"{round(seconds, 2)} seconds"
    elif seconds < HOUR:
        return f"{round(seconds / MINUTE, 2)} minutes"
    elif seconds < DAY:
        return f"{round(seconds / HOUR, 2)} hours"
    elif seconds < YEAR:
        return f"{round(seconds / DAY, 2)} days"
    elif seconds < 1000 * YEAR:
        return f"{round(seconds / YEAR, 2)} years"
    elif seconds < 1e6 * YEAR:
        return f"{round(seconds / (1000 * YEAR), 2)} thousand years"
    elif seconds < 1e9 * YEAR:
        return f"{round(seconds / (1e6 * YEAR), 2)} million years"
    elif seconds < AGE_OF_UNIVERSE:
        return f"{round(seconds / (1e9 * YEAR), 2)} billion years"
    else:
        return "longer than the age of the universe"
    
def calculate_entropy_bits(password):
    # Calculate the entropy bits of the password based on its length and character set size
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
    with open("common-words.txt", "r") as f:
        # Reads the file and splits it into a list of words
        common_words = f.read().splitlines()

    # Initialises the number of hits and the list of hits
    number_of_hits = 0
    hits = []

    # Loops through each word in the common_words list
    for word in common_words:
        # Finds the starting position of the word in the password
        startPos = password.find(word)

        # Checks whether the word was found
        if startPos != -1:
            number_of_hits += 1

            # Calculates where the word ends
            endPos = startPos + len(word)

            # Stores the word and its positions
            hits.append({
                "word": word,
                "start": startPos,
                "end": endPos
            })

    # Returns the results if any common words were found
    if number_of_hits > 0:
        return {
            "flagged": True,
            "type": "common_words",
            "matches": hits,
            "result": number_of_hits,
            "message": f"Password contains {number_of_hits} common word(s): "
                       f"{', '.join(hit['word'] for hit in hits)}"
        }

    # Returns the results if no common words were found
    return {
        "flagged": False,
        "type": "common_words",
        "matches": [],
        "result": 0,
        "message": "Password does not contain any common words."
    }

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
        groups.append({"year": string, "start": current_position - 1, "end": current_position + 3})

    # Loop through the groups list and check if any of the groups are a year between 1900 and the current year
    for group in groups:
        # Check if the group is a digit and if it is between 1900 and the current year
        if group["year"].isdigit() and 1900 <= int(group["year"]) <= datetime.datetime.now().year:
            number_of_hits += 1
            hits.append(group)
    if number_of_hits > 0:
        return {"flagged": True,
                 "type": "years",
                   "result": number_of_hits,
                   "matches": hits,
                     "message": f"Password contains years: {number_of_hits} " f"{', '.join(hit['year'] for hit in hits)}"}
    return {"flagged": False,
             "type": "years", 
             "result": 0,
             "matches": [],
             "message": "Password does not contain any years."}

def keyboard_patterns(password):
    # Define a list of common keyboard patterns
    keyboard = [ "asdfghjkl", "qwertyuiop", "zxcvbnm", "1234567890", "!@#$%^&*()"]
    chunks = []
    # Loop through the password and create chunks of 4 characters
    for i in range(len(password) - 3):
        # Create a substring of 4 characters from the password
        substring = password[i:i + 4]
        # Append the substring to the chunks list
        chunks.append({"chunk": substring, "start": i, "end": i + 4})
    # Loop through the keyboard patterns and check if any of the chunks are in the patterns
    number_of_hits = 0
    hits = []
    for pattern in keyboard:
        #  Loop through the chunks and check if any of the chunks are in the pattern or if the reverse of the chunk is in the pattern
        for chunk in chunks:
            # Check if the chunk is in the pattern or if the reverse of the chunk is in the pattern
            if chunk["chunk"] in pattern or chunk["chunk"][::-1] in pattern:
                hits.append(chunk)
                number_of_hits += 1
    if number_of_hits > 0:
        return {"flagged": True, 
                "type": "keyboard_patterns",
                  "result": number_of_hits,
                   "matches": hits,
                     "message": f"Password contains keyboard patterns: {number_of_hits}" f" {', '.join(hit['chunk'] for hit in hits)}"}
    return {"flagged": False, 
            "type": "keyboard_patterns", 
            "result": 0,
            "matches": [],
            "message": "Password does not contain keyboard patterns."}

def check_repeated_characters(password):
    # Check for repeated characters
    number_of_hits = 0
    hits = []
    for i in range(len(password) - 2):
        # Check if the current character is the same as the next two characters
        if password[i] == password[i+1] and password[i] == password[i+2]:
            # If a repeated character is found, return a dictionary with the flagged status, type, character, and message
            ch = {"character": password[i], "start": i, "end": i+3}
            number_of_hits += 1
            hits.append(ch)
    if number_of_hits > 0:
        return {"flagged": True, 
                "type": "repeated_characters",
                  "result": number_of_hits,
                  "matches": hits,
                  "message": f"Password contains repeated characters: {number_of_hits} " f"{', '.join(hit['character'] for hit in hits)}"}
    return {"flagged": False,
             "type": "repeated_characters",
               "matches": [],
               "result": 0,
                "message": "Password does not contain repeated characters."}

if __name__ == "__main__":
    # Use argparse so people can enter their passwords from the terminal
    parser = argparse.ArgumentParser()
    parser.add_argument("password")
    args = parser.parse_args()

    check_password_strength(args.password)
