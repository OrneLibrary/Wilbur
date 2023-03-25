#!/usr/bin/env python3
import argparse
import csv
import re
from datetime import datetime
from prettytable import PrettyTable


def read_csv_to_dict(filename, delimiter=','):
    with open(filename, mode='r', newline='') as csv_file:
        reader = csv.DictReader(csv_file, delimiter=delimiter)
        return [row for row in reader]


def save_dict_to_csv(file_name, data_list, delimiter=','):
    with open(file_name, 'w', newline='') as csv_file:
        if len(data_list) > 0:
            fieldnames = list(data_list[0].keys())
            writer = csv.DictWriter(
                csv_file, fieldnames=fieldnames, delimiter=delimiter)
            writer.writeheader()  # Write headers to the CSV file
            for row in data_list:
                writer.writerow(row)


def parse_ntds_dump(filename):
    """Parses the NTDS.dit dump file to extract usernames and NTHashes."""
    user_hash_list = []

    with open(filename, 'r') as file:
        for line in file:
            match = re.search(
                r'(?:(?P<domain>[\w]+)\\)?(?P<username>[\w]+):(?P<id>\d+):[^:]+:(?P<hash>[^:]+):::', line)
            if match:
                user_hash_list.append({
                    'user': match.group('username'),
                    'hash': match.group('hash')
                })

    return user_hash_list


def clean_empty_password(matches):
    """Cleans empty passwords from the matches list."""
    return [match for match in matches if match["password"]]


def calculate_password_complexity(password):
    complexity = 0
    if any(c.isdigit() for c in password):
        complexity += 1
    if any(c.islower() for c in password):
        complexity += 1
    if any(c.isupper() for c in password):
        complexity += 1
    if any(c in "!@#$%^&*()-=_+[]{}|;':\",./<>?" for c in password):
        complexity += 1
    return complexity


def generate_metrics(matches):
    pt = PrettyTable()
    pt.field_names = ["User", "Password", "Password Length",
                      "Password Complexity", "Reuse Count"]

    # Sort matches by password length
    matches.sort(key=lambda x: len(x["password"]))

    reuse_counts = {}
    complexity_counts = {i: 0 for i in range(1, 5)}
    password_users = {}

    for match in matches:
        user = match["user"]
        password = match["password"]
        password_complexity = calculate_password_complexity(password)
        if password not in reuse_counts:
            reuse_counts[password] = 0
            password_users[password] = []
        reuse_counts[password] += 1
        complexity_counts[password_complexity] += 1
        password_users[password].append(user)

    for match in matches:
        user = match["user"]
        password = match["password"]
        password_length = len(password)
        password_complexity = calculate_password_complexity(password)
        reuse_count = reuse_counts[password]
        pt.add_row([user, password, password_length,
                   password_complexity, reuse_count])

    pt_shared = PrettyTable()
    pt_shared.field_names = ["Password", "Users"]

    for password, users in password_users.items():
        if len(users) > 1:
            pt_shared.add_row([password, ", ".join(users)])

    output_filename = datetime.now().strftime("%Y%m%d_%H%M%S") + "_metrics.txt"
    with open(output_filename, "w") as f:
        f.write(pt.get_string())
        f.write("\n\nPassword Complexity Counts:\n")
        for complexity, count in complexity_counts.items():
            f.write(f"Complexity {complexity}: {count}\n")
        f.write("\nUsers with Shared Passwords:\n")
        f.write(pt_shared.get_string())

    print(f"Metrics results saved to {output_filename}")


def create_hash_password_csv(filename):
    """Create a CSV file with headers 'hash' and 'password'."""
    with open(filename, mode='w', newline='') as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=[
                                'hash', 'password'], delimiter=':')
        writer.writeheader()


def create_csv(filename, fieldnames, delimiter):
    with open(filename, mode='w', newline='') as csv_file:
        writer = csv.DictWriter(
            csv_file, fieldnames=fieldnames, delimiter=delimiter)
        writer.writeheader()


def save_cleaned_hashes(user_hash_list):
    current_time = datetime.now().strftime('%Y%m%d_%H%M%S')
    output_filename = f"{current_time}_cleaned.txt"

    with open(output_filename, "w") as f:
        for item in user_hash_list:
            f.write(item["hash"] + "\n")
    print(
        f"Cleaned hashes saved to {output_filename}, ready for upload to Hashtopolis.")


def save_crackhound_format(matches, domain):
    domain = domain.upper()

    current_time = datetime.now().strftime('%Y%m%d_%H%M%S')
    output_filename = f"{current_time}_crackhound.txt"

    with open(output_filename, "w") as f:
        for match in matches:
            user = match["user"].upper()
            hash_value = match["hash"]
            password = match["password"]
            f.write(f"{domain}\\{user}:{hash_value}:{password}\n")
    print(f"Crackhound results saved to {output_filename}")


def main():
    """Script to parse NTDS.dit Data with cracked hashes from Hashtopolis."""
    parser = argparse.ArgumentParser(
        description='''This script assist you in cleaning NTDS.dit and generating needed files.
            :param a: Ensure all files are in the SAME DIRECTORY when running this script.
            To generate user_hash.csv and hash_password.csv files, use --generate.

            Example usage:
            1. Python3 UHP.py NTDS_DUMP.txt - To generate a clean hash file to upload to Hashtopolis for cracking.
            2. Next, update the hash_password.csv file with the cracked passwords from Hashtopolis.
            3. Then run Python3 UHP.py -d <DOMAIN.LOCAL>. This will generate three files for you:
                - matched.csv: which will include the username and cleartext password.
                - metrics.txt: which will include different metrics about password usage.
                - crackhound.txt: which will be used by Crackhound to mark users owned and add plaintext password to object in Bloodhound.''',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    parser.add_argument(
        "--generate",
        action="store_true",
        dest="generate",
        default=False,
        help="Generate CSV files with headers only.",
    )

    parser.add_argument(
        "NTDS_DUMP",
        action="store",
        nargs='?',  # Make this argument optional
        default=None,
        help="The NTDS.dit dump file.",
    )

    parser.add_argument(
        "-d", "--domain",
        action="store",
        dest="domain",
        default=None,
        help="Specify the domain name.",
    )

    args = parser.parse_args()

    if args.generate:
        create_csv('user_hash.csv', ['user', 'hash'], ':')
        create_csv('hash_password.csv', ['hash', 'password'], ':')
    elif args.NTDS_DUMP:
        ntds_dump = args.NTDS_DUMP
        user_hash_list = parse_ntds_dump(ntds_dump)
        save_dict_to_csv('user_hash.csv', user_hash_list, ':')
        save_cleaned_hashes(user_hash_list)
        create_csv('hash_password.csv', ['hash', 'password'], ':')

    else:
        user_hash_list = read_csv_to_dict('user_hash.csv', ':')
        hash_password_list = read_csv_to_dict('hash_password.csv', ':')

        matches = [
            {"user": user["user"], "hash": password["hash"],
             "password": password["password"]}
            for user in user_hash_list
            for password in hash_password_list
            if user["hash"] == password["hash"]
        ]

        current_time = datetime.now().strftime('%Y%m%d_%H%M%S')
        save_dict_to_csv(f'{current_time}_matched.csv', matches, ':')
        print(f"Matched results saved to {current_time}_matched.csv")
        generate_metrics(matches)
        if args.NTDS_DUMP:
            save_crackhound_format(matches, args.NTDS_DUMP)
        if args.domain:
            save_crackhound_format(matches, args.domain)


if __name__ == "__main__":
    main()
