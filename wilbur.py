#!/usr/bin/env python3

# Standard Python Libraries
import argparse
import collections
import csv
from itertools import islice

SPECIAL_CHARACTER = """!@#$%^&*()-+?_=,<>/"""


def take(n, iterable):
    "Return first n items of the iterable as a list"
    return list(islice(iterable, n))


def load_csv_to_dict(filename):
    """Loads csv to list of dicts."""

    _list = list()
    with open(filename, mode="r", encoding="utf-8") as csv_file:
        csv_reader = csv.DictReader(csv_file, delimiter=":")
        _list = list()
        for row in csv_reader:
            _list.append(row)

    return _list


def save_dict_to_csv(filename, _list):
    """Save list of dicts to csv"""

    with open(filename, mode="w") as csv_file:
        fieldnames = ["user", "hash", "password"]
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)

        writer.writeheader()
        for row in _list:
            writer.writerow(row)


def clean_empty_password(matchs):
    """Cleans empty passwords from the matchs list."""
    clean_match = list()
    for match in matchs:
        if match["password"] and match["password"] != "":
            clean_match.append(match)

    return clean_match


def get_password_complexity(matchs):
    """Return a list of tuples for the complexity of each password."""
    passwords = dict()
    for match in clean_empty_password(matchs):
        passwords[match["password"]] = 0
        if any(char.islower() for char in match["password"]):
            passwords[match["password"]] += 1
        if any(char.isupper() for char in match["password"]):
            passwords[match["password"]] += 1
        if any(char.isdigit() for char in match["password"]):
            passwords[match["password"]] += 1
        if any(char in SPECIAL_CHARACTER for char in match["password"]):
            passwords[match["password"]] += 1

    complexity = {1: 0, 2: 0, 3: 0, 4: 0}
    for count in passwords.values():
        complexity[count] += 1

    return complexity


def get_password_length(matchs):
    """Return a dict of password length and the count of that length."""
    length_count = dict()
    for match in clean_empty_password(matchs):
        password_length = len(match["password"])
        if password_length in length_count.keys():
            length_count[password_length] += 1
        else:
            length_count[password_length] = 1

    # Orders list based on
    length_count = collections.OrderedDict(sorted(length_count.items()))

    return length_count


def get_password_reuse(matchs, num):
    """Returns a list of tuples for the num highest password reuses."""
    passwords = dict()
    for match in clean_empty_password(matchs):
        if f'{match["password"]}' in passwords.keys():
            passwords[f'{match["password"]}'] += 1
        else:
            passwords[f'{match["password"]}'] = 1

    return take(
        num,
        dict(sorted(passwords.items(), key=lambda item: item[1], reverse=True)).items(),
    )


def get_username_password_match(matchs):
    """Return a count of instances where username and password match."""

    user_pass_match_list = list()

    for match in matchs:
        if "\\" in match["user"]:
            username = match["user"].split("\\")[1]
        if username == match["password"]:
            user_pass_match_list.append(match)

    return user_pass_match_list


def output_metrics(matchs, num):
    """Out puts the metrics to a markdown file."""

    output_list = []

    # Builds the Complexity count table.
    output_list.append("|Complexity|Count|")
    output_list.append("|--|--|")

    complexities = get_password_complexity(matchs)
    for complexity, count in complexities.items():
        output_list.append(f"|{complexity}|{count}|")

    # Build password reuse list.
    get_password_reuse(matchs, num)

    output_list.append(f"<br>The top {num} passwords:")
    output_list.append("")
    output_list.append("|Count|Password|")
    output_list.append("|--|--|")
    reused_passwords = get_password_reuse(matchs, num)
    for password in reused_passwords:

        output_list.append(f"|{password[1]}|{password[0]}|")

    output_list.append("<br>The password lengths:")
    output_list.append("")
    output_list.append("|Length|Count|")
    output_list.append("|--|--|")

    password_length_dict = get_password_length(matchs)
    for length, count in password_length_dict.items():
        output_list.append(f"|{length}|{count}|")

    return output_list


def output_owned(matchs):
    """Retruns a list of owned usernames with domains.

    Args:
        matchs (_type_): _description_

    Returns:
        list(strings): Returns a list of usernames with domains
        formated as username@domain.
    """

    owned_users = list()

    for match in matchs:
        split_user = match["user"].split("\\")
        owned_users.append(f"{split_user[1]}@{split_user[0]}")

    return owned_users


def main():
    """Merge a list of user name with hashes and a list of password with hashes."""
    """Set up logging, connect to Postgres, call requested function(s)."""
    parser = argparse.ArgumentParser(
        description="Merge two files which contain usernames with hashes and passwords with hashes.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    parser.add_argument(
        "--no-output",
        action="store_true",
        dest="no_output",
        default=False,
        help="Prevent the output of matches.cvs.",
    )

    parser.add_argument(
        "-s",
        "--same",
        dest="same",
        action="store_true",
        default=True,
        help="Saves a list matching username and passwords.",
    )

    parser.add_argument(
        "-r",
        "--reuse",
        action="store",
        dest="reuse",
        default=10,
        type=int,
        help="Return the top number of password's that get reused.",
    )

    parser.add_argument(
        "PASSWORD_FILE",
        action="store",
        help="The file holding password and hash.",
    )
    parser.add_argument(
        "USER_FILE",
        action="store",
        help="The file holding username and hash.",
    )

    args = parser.parse_args()

    # Load files into lists.
    passwords = load_csv_to_dict(args.PASSWORD_FILE)
    users = load_csv_to_dict(args.USER_FILE)

    matchs = list()

    for user in users:
        for password in passwords:
            if user["hash"] == password["hash"]:
                matchs.append(
                    {
                        "user": user["user"],
                        "hash": user["hash"],
                        "password": password["password"],
                    }
                )

    if not args.no_output:
        save_dict_to_csv("matched.csv", matchs)

        print()
        print('matchs saved to "matched.csv"')
        print()

    if args.same:
        save_dict_to_csv("same.csv", get_username_password_match(matchs))

        print('Matching username nad passwords saved to "same.txt"')

    print('The metrics saved to "metrics.md"')

    metrics_output_list = output_metrics(matchs, args.reuse)
    with open("metrics.md", "w") as fp:
        for line in metrics_output_list:
            fp.write(f"{line}")

    print('Owned users saved to "owned.txt"')

    owned_output_list = output_owned(matchs)
    with open("owned.txt", "w") as fp:
        for line in owned_output_list:
            fp.write(f"{line}")

    print()
    print("Some people know things about the universe that nobody")
    print("ought to know, and can do things that nobody ought to")
    print("be able to do. -H.P. Lovecraft")


if __name__ == "__main__":
    main()
