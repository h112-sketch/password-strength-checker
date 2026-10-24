# Modules

import os
import datetime


WORD_LIST_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "common-words.txt")
    


def check_common_words(password):
    # Finds every word from common-words.txt that appears in the password.
    # Known limitation: find() only returns the first place each word appears.
    with open(WORD_LIST_PATH, "r") as f:
        common_words = f.read().splitlines()

    hits = []
    for word in common_words:
        start_pos = password.find(word)
        if start_pos != -1:
            hits.append({"word": word, "start": start_pos, "end": start_pos + len(word)})

    return {"type": "common_words", "matches": hits}


def check_years(password):
    # Finds every 4-digit year from 1900 to the current year
    current_year = datetime.datetime.now().year
    hits = []
    for i in range(len(password) - 3):
        group = password[i:i + 4]
        if group.isdigit() and 1900 <= int(group) <= current_year:
            hits.append({"year": group, "start": i, "end": i + 4})

    return {"type": "years", "matches": hits}


def keyboard_patterns(password):
    # Finds 4-character runs along a keyboard row, forwards or backwards
    keyboard = ["asdfghjkl", "qwertyuiop", "zxcvbnm", "1234567890", "!@#$%^&*()"]
    hits = []
    for i in range(len(password) - 3):
        chunk = password[i:i + 4]
        for row in keyboard:
            if chunk in row or chunk[::-1] in row:
                hits.append({"chunk": chunk, "start": i, "end": i + 4})

    return {"type": "keyboard_patterns", "matches": hits}


def check_repeated_characters(password):
    # Finds runs of the same character three times in a row
    hits = []
    for i in range(len(password) - 2):
        if password[i] == password[i + 1] == password[i + 2]:
            hits.append({"character": password[i], "start": i, "end": i + 3})

    return {"type": "repeated_characters", "matches": hits}

