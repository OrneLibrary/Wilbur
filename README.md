# UHP.py #

## A new and improved Wilbur.py that acutally works ##

A python utility to match two colon delimited files containing usernames, hashes, and cracked passwords. Will also include different metrics about the cracked passwords. Will also generate a Crackhound file to be used with Crackhound.py.

## ALL FILES MUST BE WITHIN THE SAME DIRECTORY ##

## Functions ##

Generate a clean hash list to be uploaded to Hashtopolis.

`Python3 ./UHP.py <NTDS_DUMP>`

Example:

`Python3 ./UHP.py NTDS_DUMP.txt`

This will generate a cleaned.txt file of all parsed user NT hashes that can be uploaded to Hashtopolis for cracking. 
This will also generate two CSV files that will be used next. 

- user_hash.csv : CSV file that will have USERNAME:NTHASH.
- hash_password.csv : CSV file that YOU will update with cracked hashes in the format of HASH:ClearTextPassword.

After updating hash_password.csv with the cracked passwords run the following:

`Python3 ./UHP.py -d <DOMAIN.LOCAL>`

Example:

`Python3 ./UHP.py -d CPT.LOCAL`
 
This will generate three files.

- matched.csv : Will have all USERS matched with CLEARTEXT passwords.
- metrics.txt : Will have a varity of different metrics on the cracked passwords.
- crackhound.txt : Ready to be ran with Crackhound.py to update Bloodhound

Example Output:

```python
 python3 ../UHP.py NTDS_DUMP.txt
  Cleaned hashes saved to 20230325_001256_cleaned.txt, ready for upload to Hashtopolis.
```

```
cat 20230325_001256_cleaned.txt
23e1d10001876b0078a9a779017fc025
31d6cfe0d16ae931b73c59d7e0c089c0
c82d13d85e7f4d04b8614295063c1e28
23e1d10001876b0078a9a779017fc026
23e1d10001876b0078a9a779017fc027
23e1d10001876b0078a9a779017fc028
23e1d10001876b0078a9a779017fc029
23e1d10001876b0078a9a779017fc030
23e1d10001876b0078a9a779017fc031
23e1d10001876b0078a9a779017fc032
23e1d10001876b0078a9a779017fc032
```

```python
python3 ../UHP.py -d CPT.LOCAL
Matched results saved to 20230325_001523_matched.csv
Metrics results saved to 20230325_001523_metrics.txt
Crackhound results saved to 20230325_001523_crackhound.tx
```

