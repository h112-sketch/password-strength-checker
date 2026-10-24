
import math

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


