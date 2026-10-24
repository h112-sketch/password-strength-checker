# Modules
import argparse
import datetime
import math
import os

# Cost in bits of each pattern type: log2 of how many possibilities an attacker would try
costs = {
    "years": 7,                   # ~127 years (1900 to now)
    "common_words": 13.3,         # 10,001 words in common-words.txt
    "keyboard_patterns": 6,       # 31 chunks, doubled for reversals = 62
    "repeated_characters": 6.6    # 95 possible characters
}

# How fast each kind of attacker can guess (guesses per second)
attacker_speeds = {
    "online": 10,         # guessing through a login page, which slows attackers down
    "offline": 10 ** 10   # stolen database of fast hashes, cracked with GPUs
}

# The word list sits next to this file, so it is found wherever the program is run from
WORD_LIST_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "common-words.txt")


def check_password_strength(original_password):
    entropy = calculate_entropy_bits(original_password)
    # Pattern checks are case-insensitive, so they run on a lowercase copy
    password = original_password.lower()

    check_results = [
        check_common_words(password),
        check_years(password),
        keyboard_patterns(password),
        check_repeated_characters(password),
    ]

    # Gather every match into one list, labelling each with the check that found it
    all_matches = []
    for result in check_results:
        for match in result["matches"]:
            match["type"] = result["type"]
            all_matches.append(match)

    # Longest matches first, so they win when matches overlap
    all_matches.sort(reverse=True, key=lambda x: x["end"] - x["start"])

    # Accept a match only if none of its characters are already explained by an earlier match
    claimed_positions = set()
    total_cost = 0
    accepted_matches = []
    for match in all_matches:
        if any(pos in claimed_positions for pos in range(match["start"], match["end"])):
            continue
        claimed_positions.update(range(match["start"], match["end"]))
        total_cost += costs[match["type"]]
        accepted_matches.append(match)

    # Characters not covered by any pattern are treated as random.
    # Uses the original password so uppercase letters still count towards the character set.
    left_over_string = ""
    for i in range(len(original_password)):
        if i not in claimed_positions:
            left_over_string += original_password[i]

    leftover_bits = calculate_entropy_bits(left_over_string)
    final_bits = total_cost + leftover_bits

    guesses = 2 ** final_bits
    online_crack_time = guesses / attacker_speeds["online"]
    offline_crack_time = guesses / attacker_speeds["offline"]

    score, strength = score_password_strength(final_bits)
    feedback_messages = calculate_feedback_message(accepted_matches, original_password)

    return {
        "original_password": original_password,
        "score": score,
        "strength": strength,
        "entropy": entropy,
        "total_cost": total_cost,
        "left_over_string": left_over_string,
        "leftover_bits": leftover_bits,
        "final_bits": final_bits,
        "guesses": guesses,
        "online_crack_time": online_crack_time,
        "offline_crack_time": offline_crack_time,
        "accepted_matches": accepted_matches,
        "feedback_messages": feedback_messages,
    }


def calculate_feedback_message(accepted_matches, original_password):
    feedback_messages = []
    for match in accepted_matches:
        # Slice the original password so the tip shows exactly what the user typed
        section = original_password[match["start"]:match["end"]]
        if match["type"] == "common_words":
            feedback_messages.append(f"Avoid common words like '{section}' in your password.")
        elif match["type"] == "years":
            feedback_messages.append(f"Avoid using years like '{section}' in your password.")
        elif match["type"] == "keyboard_patterns":
            feedback_messages.append(f"Avoid keyboard patterns like '{section}' in your password.")
        elif match["type"] == "repeated_characters":
            feedback_messages.append(f"Avoid repeated characters like '{section}' in your password.")
    return feedback_messages


def display_results(results):
    print("--------------------------------------------------")
    print(f"Password: {results['original_password']}")
    print("Leftover string:", results['left_over_string'])
    print("Naive entropy (whole password as random):", round(results['entropy'], 1), "bits")
    print("Pattern cost:", results['total_cost'], "bits")
    print("Leftover bits:", round(results['leftover_bits'], 1), "bits")
    print("Final estimate:", round(results['final_bits'], 1), "bits")
    print("Estimated guesses:", round(results['guesses'], 1))
    print("Estimated online crack time:", turn_to_readable_time(results['online_crack_time']))
    print("Estimated offline crack time:", turn_to_readable_time(results['offline_crack_time']))
    print(f"Password strength score: {results['score']} ({results['strength']})")

    for message in results['feedback_messages']:
        print(message)

    if results['score'] <= 1:
        print("Your password is weak. Consider using a longer password with a mix of letters, numbers, and symbols.")
    elif results['score'] >= 3:
        print("Your password is good overall.")


def score_password_strength(final_bits):
    # Bands loosely based on zxcvbn's thresholds
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
    # Bits if every character were random: length x log2(character set size)
    character_set_size = calculate_character_set_size(password)
    if character_set_size == 0:
        return 0
    return len(password) * math.log2(character_set_size)


def calculate_character_set_size(password):
    # Size of the character set an attacker would need, based on the types of character used
    character_set_size = 0
    if any(c.islower() for c in password):
        character_set_size += 26
    if any(c.isupper() for c in password):
        character_set_size += 26
    if any(c.isdigit() for c in password):
        character_set_size += 10
    if any(c in "!@#$%^&*()-_=+[{]}\\|;:'\",<.>/?`~" for c in password):
        character_set_size += 33
    return character_set_size


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


if __name__ == "__main__":
    # Use argparse so people can enter their passwords from the terminal
    parser = argparse.ArgumentParser()
    parser.add_argument("password")
    args = parser.parse_args()

    results = check_password_strength(args.password)
    display_results(results)
