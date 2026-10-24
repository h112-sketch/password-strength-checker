import pytest

from password_checker import (
    check_password_strength,
    check_common_words,
    check_years,
    keyboard_patterns,
    check_repeated_characters,
    calculate_entropy_bits,
    calculate_character_set_size,
    score_password_strength,
    turn_to_readable_time,
)


# ---------- Overall scores ----------

@pytest.mark.parametrize("password, expected_score", [
    ("password", 1),                    # most common password, one 13.3-bit word
    ("qwerty123", 1),                   # whole thing is in the word list
    ("monkey1998", 2),                  # 'monkey1' + leftover '998'
    ("correcthorsebatterystaple", 4),   # long passphrase
    ("x7#Kq!9vLm2$", 4),                # random, no patterns
    ("", 0),                            # empty password
])

def test_overall_score(password, expected_score):
    assert check_password_strength(password)["score"] == expected_score


def test_patterns_make_password_weaker_than_naive_entropy():
    result = check_password_strength("monkey1998")
    assert result["final_bits"] < result["entropy"]


def test_uppercase_raises_score_of_leftover_characters():
    # Regression: leftover must be taken from the original password, not the lowercase copy
    lower = check_password_strength("xyz1998")["final_bits"]
    mixed = check_password_strength("XyZ1998")["final_bits"]
    assert mixed > lower


def test_case_does_not_stop_pattern_detection():
    assert check_password_strength("MONKEY1998")["score"] == check_password_strength("monkey1998")["score"]


@pytest.mark.parametrize("password", ["é漢字🔒", "    ", "£££"])
def test_unusual_input_does_not_crash(password):
    check_password_strength(password)


# ---------- Overlapping matches ----------

def test_overlapping_matches_only_counted_once():
    # 'monkey', 'monkey1' and 'monk' all overlap; only the longest should be accepted
    result = check_password_strength("monkey1998")
    accepted = [m for m in result["accepted_matches"] if m["type"] == "common_words"]
    assert len(accepted) == 1
    assert accepted[0]["start"] == 0 and accepted[0]["end"] == 7


def test_no_positions_claimed_twice():
    result = check_password_strength("qwertyuiop1998aaa")
    positions = []
    for match in result["accepted_matches"]:
        positions.extend(range(match["start"], match["end"]))
    assert len(positions) == len(set(positions))


# ---------- Individual checks ----------

def test_common_word_found_with_positions():
    matches = check_common_words("xxmonkeyxx")["matches"]
    assert {"word": "monkey", "start": 2, "end": 8} in matches


def test_no_common_words_in_random_string():
    assert check_common_words("x7#kq!9v")["matches"] == []


def test_year_found_with_positions():
    assert check_years("abc1998")["matches"] == [{"year": "1998", "start": 3, "end": 7}]


def test_year_not_aligned_to_blocks_of_four():
    # Regression: the first version split the password into fixed blocks and missed this
    assert len(check_years("a1998")["matches"]) == 1


@pytest.mark.parametrize("password", ["1899", "3000", "abcd"])
def test_non_years_ignored(password):
    assert check_years(password)["matches"] == []


def test_keyboard_pattern_found():
    assert len(keyboard_patterns("qwer")["matches"]) == 1


def test_reversed_keyboard_pattern_found():
    # Regression: reversed checking was lost in one version
    assert len(keyboard_patterns("ytrewq")["matches"]) > 0


def test_keyboard_rows_do_not_join_up():
    # Regression: an old joined-up row made 'opas' look like a pattern
    assert keyboard_patterns("opas")["matches"] == []


def test_repeated_characters_found_with_positions():
    assert check_repeated_characters("abccc")["matches"] == [{"character": "c", "start": 2, "end": 5}]


def test_two_in_a_row_is_not_a_repeat():
    # Regression: the first version flagged any character used 3+ times anywhere, e.g. 'banana'
    assert check_repeated_characters("banana")["matches"] == []


# ---------- Entropy and character set ----------

@pytest.mark.parametrize("password, expected_size", [
    ("abc", 26),
    ("aBc", 52),
    ("abc1", 36),
    ("a!", 59),
    ("a|", 59),       # the backslash-escaped pipe is in the symbol set
    ("", 0),
])
def test_character_set_size(password, expected_size):
    assert calculate_character_set_size(password) == expected_size


def test_entropy_of_empty_string_is_zero():
    assert calculate_entropy_bits("") == 0


def test_entropy_matches_formula():
    # 3 lowercase letters: 3 x log2(26), about 14.1
    assert calculate_entropy_bits("xyz") == pytest.approx(14.1, abs=0.1)


# ---------- Scoring and crack time ----------

@pytest.mark.parametrize("bits, expected_score", [
    (0, 0), (9.9, 0), (10, 1), (19.9, 1), (20, 2), (27, 3), (33, 4), (100, 4),
])
def test_score_bands(bits, expected_score):
    assert score_password_strength(bits)[0] == expected_score


@pytest.mark.parametrize("seconds, expected", [
    (0.5, "less than a second"),
    (30, "30 seconds"),
    (120, "2.0 minutes"),
    (2 * 24 * 3600, "2.0 days"),
    (1e30, "longer than the age of the universe"),
])
def test_readable_time(seconds, expected):
    assert turn_to_readable_time(seconds) == expected


# ---------- Feedback ----------

def test_feedback_names_the_pattern_as_typed():
    feedback = check_password_strength("MONKEY1998")["feedback_messages"]
    assert any("MONKEY1" in message for message in feedback)


def test_no_feedback_for_random_password():
    assert check_password_strength("x7#Kq!9vLm2$")["feedback_messages"] == []


# ---------- Known limitations (expected to fail for now) ----------

@pytest.mark.xfail(reason="No leetspeak handling yet: P@ssw0rd1! is not recognised as 'password'")
def test_leetspeak_password_is_weak():
    assert check_password_strength("P@ssw0rd1!")["score"] <= 1


@pytest.mark.xfail(reason="Greedy matching picks 'monkey1' and leaves '998' as random, "
                          "instead of the cheaper 'monkey' + year '1998'")
def test_cheapest_split_is_used():
    assert check_password_strength("monkey1998")["final_bits"] < 21
