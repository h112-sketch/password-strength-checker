# Password Strength Checker
Haris Mehmood

A Python program that evaluates the strengths of different passwords provided. Compared to basic password strength checkers, this password strength checker estimates how many guesses an attacker would need to crack your password.

## Features

- Check Common Words: This feature detects any common words within a password.
- Check Years: This feature checks for any years (e.g. 2026) within a password.
- Check Keyboard Patterns: This feature checks for any keyboard patterns (e.g. qwerty) within the password.
- Repeated Characters: Checks for any repeated characters within a password.
- Entropy Bits & Crack Time: Characters covered by a pattern are replaced by that pattern's cost. The leftover characters in the password are passed into an entropy function which calculates the leftover bits. The total cost + leftover bits are combined and this is then given a score from 0-4 based on how strong the password is. It also provides a crack time (time it would take to crack the password) for an online and offline attacker using an estimate of the number of guesses per second for the attacker.
- Feedback: The program provides feedback for the user depending on why their password is weak, for example it can provide feedback asking the user to not repeat characters and also highlights what specific characters were weak.

## Installation

To run this program you should have Python version 3 alongside pytest version 9.

Commands:

```bash
git clone https://github.com/haris-221/password-strength-checker.git
cd password-strength-checker
pip install pytest   # only needed for running the tests
```

## Usage

To run this program type `python main.py` in the terminal followed by a password.

Example:

```bash
python main.py monkey1998
```

Expected Output:

```
--------------------------------------------------
Password: monkey1998
Leftover string: 998
Naive entropy (whole password as random): 51.7 bits
Pattern cost: 13.3 bits
Leftover bits: 10.0 bits
Final estimate: 23.3 bits
Estimated guesses: 10085535.0
Estimated online crack time: 11.67 days
Estimated offline crack time: less than a second
Password strength score: 2 (Fair)
Avoid common words like 'monkey1' in your password.
```

Passwords typed as command line arguments are saved into your terminal history, so don't test your real passwords using this program.

## How it works

The program first searches the password for each of the patterns: common words, keyboard patterns, repeated characters and years. It then determines which of these patterns was found within the password and applies a cost (bits) for each (outlined below).

```python
costs = {
    "years": 7,                   # ~127 years (1900 to now)
    "common_words": 13.3,         # 10,001 words in common-words.txt
    "keyboard_patterns": 6,       # 31 chunks, doubled for reversals = 62
    "repeated_characters": 6.6    # 95 possible characters
}
```

These patterns are then removed from the password, and any leftover characters are treated as random. These random characters are converted into the total bits and the crack time is then determined from this. And this is then converted into the score.

### monkey1998

monkey1998 has 10 characters, which are either lowercase or digits. `calculate_character_set_size` returns a charset of 36. This is then used in `calculate_entropy_bits`, which returns the calculation of the length of the password multiplied by log2 of the character set size. This provides a result of 51.7 bits.

The program then checks if any patterns are within the password, starting with common words. It finds monkey1 and monkey as common words within the password and the program uses the longest matching first, therefore monkey1 is used rather than monkey. This leaves 998 as leftover characters which are not matched by any pattern.

For one common word (monkey1) a pattern cost of 13.3 is applied, calculated from the 10,001 words in common-words.txt. The leftover characters (998) are calculated to result in a total of 10 bits due to it being digits only. The total bits calculated is then 13.3 + 10, which is 23.3. If you treat the entire password as random, as explained above, the total bits is 51.7, however with the pattern cost this is reduced down to 23.3.

A crack time is then calculated: for an online attacker this is 10 guesses per second, and for an offline attacker this is 10 ** 10 guesses per second. The number of guesses calculated for a password is 2 ** final bits. For this password this amounts to 11.67 days for an online attacker to crack the password, and for an offline attacker it would take less than a second.

A final score is provided and 23.3 falls into a password strength score of 2 (Fair).

## Results Table

"Naive bits" treats the whole password as random characters. "Final bits" is this program's estimate after patterns are found.

| Password | Naive bits | Final bits | Score | Online crack time | Patterns found |
|---|---|---|---|---|---|
| `password` | 37.6 | 13.3 | 1 (Weak) | 16.81 minutes | common word `password` |
| `qwerty123` | 46.5 | 13.3 | 1 (Weak) | 16.81 minutes | common word `qwerty123` |
| `monkey1998` | 51.7 | 23.3 | 2 (Fair) | 11.67 days | common word `monkey1` |
| `Summer2024` | 59.5 | 20.3 | 2 (Fair) | 1.49 days | common word `Summer`, year `2024` |
| `xk9#mQ` | 39.4 | 39.4 | 4 (Strong) | 2.33 thousand years | none |
| `correcthorsebatterystaple` | 117.5 | 87.7 | 4 (Strong) | longer than the age of the universe | common words `battery`, `horse` |
| `x7#Kq!9vLm2$` | 78.8 | 78.8 | 4 (Strong) | longer than the age of the universe | none |
| `P@ssw0rd1!` | 65.7 | 65.7 | 4 (Strong) | longer than the age of the universe | none (see Limitations) |

The first four rows show the main result: passwords that look reasonable when treated as random (37–60 bits) drop to 13–23 bits once their patterns are found. The last row shows the leetspeak limitation, where `P@ssw0rd1!` is not recognised as `password`.

## Program Structure

- `display.py`: Manages the output provided to the user alongside feedback messages
- `main.py`: Runs the pattern checks, combines the costs, works out the leftover bits and calculates the score
- `maths.py`: Computes maths calculations
- `patterns.py`: Responsible for finding patterns within the password
- `test_checker.py`: Python file for testing purposes

## Running the tests

To run the 49 tests plus the 2 expected to fail, type `python -m pytest` into the terminal. The tests cover all pattern logic and the expected scores, entropy, crack time and expected outputs from the passwords.

## Limitations and future work

The program fails on leetspeak, for example if a user were to type P@ssw0rd1! the program would not determine this as a weak password, instead returning a score of 4 (Strong). `find()` only finds the first occurrence of the phrase rather than checking the entire string. Furthermore greedy matching is a weakness in the program, where if a password like monkey1998 was inputted the program would match monkey1 and leave 998 as random characters, whereas the better option would be matching monkey and 1998. Word popularity is also a weakness in the program, it does not differentiate between the popularity of the word when scoring, each common word costs a fixed total of 13.3 bits, regardless if it is the #1 most common word in the world or #10,001. Finally the score bands are set for online attackers, xk9#mQ as revealed in the results table is only 6 characters long and would fail in about a minute using an offline attacker, however the program determines this as a Strong (4) password. Short random passwords look stronger than they actually are.

## References

- D. L. Wheeler, "zxcvbn: Low-Budget Password Strength Estimation", USENIX Security 2016. https://www.usenix.org/system/files/conference/usenixsecurity16/sec16_paper_wheeler.pdf
- NIST SP 800-63B, Digital Identity Guidelines: Authentication and Lifecycle Management. https://pages.nist.gov/800-63-3/sp800-63b.html
