from maths import turn_to_readable_time


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
