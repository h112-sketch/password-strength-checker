# Modules
import argparse

from patterns import (
    check_common_words,
    check_years,
    keyboard_patterns,
    check_repeated_characters,
)

from maths import (
    calculate_entropy_bits,
    score_password_strength,
    calculate_character_set_size,
    turn_to_readable_time,
)

from display import (
    calculate_feedback_message,
    display_results,
)

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





if __name__ == "__main__":
    # Use argparse so people can enter their passwords from the terminal
    parser = argparse.ArgumentParser()
    parser.add_argument("password")
    args = parser.parse_args()

    results = check_password_strength(args.password)
    display_results(results)
