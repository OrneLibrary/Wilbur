# Wilbur #

A python utility to match two csv files containing usernames, hashes, and cracked passwords.

## Functions ##
 
Matches cracked passwords and the hash with the username from two CSV files. Run the following command:

`./wilbur.py <PASSWORD-FILE> <USER-FILE>`

Both input files should have the following **headers**:

Password File: `hash,password`

User File: `hash,user`