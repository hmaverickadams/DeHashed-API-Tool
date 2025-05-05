# DeHashed-API-Tool
A command-line tool to query the Dehashed API. Easily search for various parameters like usernames, emails, hashed passwords, IP addresses, and more.

## Features
- Search the Dehashed API using multiple parameters.
- Output unique results to a CSV file.
- Fetch unique password results.
- Silent output mode for minimal console output.

## Installation
### Prerequisites
1. Ensure you have Python 3.x installed.
2. A valid DeHashed account, API key, and paid API credits are required.
3. Ensure pip or pipx is installed (pipx recommended)

### Pipx install
```bash
pipx install git+https://github.com/hmaverickadams/DeHashed-API-Tool
```

> **NOTE**: You can also install with regular pip using `pip install git+https://github.com/hmaverickadams/DeHashed-API-Tool` but pipx is recommended to ensure you don't break python dependencies to other packages.

### Add API Credential
The API email and key input for each request or stored in the config.txt file (in cleartext)

**Run without storing keys**
```bash
dehashapitool -u username --key
```
> **NOTE**: You will be prompted for the API key

**Store Keys in config.txt file (Key prompted)**
```bash
dat --store-creds
```

> **NOTE**: `dat` can be used as the command instead of `dehashapitool` to save some keystrokes, but either one will run the script.

**Run with stored keys**
```bash
dat -u username
```

## Usage
### Running the tool:
`dehashapitool -h`

### Options:
```
usage: dehashapitool [-h] [-a ADDRESS] [-e EMAIL] [-H HASHED_PASSWORD] [-i IP_ADDRESS] [-n NAME] [-p PASSWORD] [-P PHONE] [-u USERNAME] [-v VIN] [-d DOMAIN] [-o OUTPUT] [-oS OUTPUT_SILENTLY]
                     [-s SIZE] [--only-passwords] [--regex] [--key [DEHASHED_KEY]] [--store-key]

Query the Dehashed API

options:
  -h, --help            show this help message and exit
  -a ADDRESS, --address ADDRESS
                        Specify the address
  -e EMAIL, --email EMAIL
                        Specify the email
  -H HASHED_PASSWORD, --hashed_password HASHED_PASSWORD
                        Specify the hashed password
  -i IP_ADDRESS, --ip_address IP_ADDRESS
                        Specify the IP address
  -n NAME, --name NAME  Specify the name
  -p PASSWORD, --password PASSWORD
                        Specify the password
  -P PHONE, --phone PHONE
                        Specify the phone number
  -u USERNAME, --username USERNAME
                        Specify the username
  -v VIN, --vin VIN     Specify the VIN
  -d DOMAIN, --domain DOMAIN
                        Specify the domain
  -o OUTPUT, --output OUTPUT
                        Outputs to CSV. A file name is required.
  -oS OUTPUT_SILENTLY, --output_silently OUTPUT_SILENTLY
                        Outputs to CSV silently. A file name is required.
  -s SIZE, --size SIZE  Specify the size, between 1 and 10000
  --only-passwords      Return only passwords
  --regex               Use regex search instead of string (seems to be broken as of May 2025)

API Arguments:
  Arguments related to Dehashed API credentials

  --key [DEHASHED_KEY], --dehashed-key [DEHASHED_KEY]
                        Dehashed API key (overrides config.txt value)
  --store-key           Stored the Dehashed API key in cleartext in the config.txt file (overrides previous config.txt values)

Usage examples:
  dat --key <API_KEY> --store-creds
  dehashapitool -u username
  dehashapitool -e email@example.com --output results.csv
  dat -d example.com --only-passwords
  dat -i 192.168.0.1 -s 100 -de jdoe@example.com --key
```

### Basic Usage:
`dehashapitool -u username`

The above will return all results for the queried username.

### Output Unique Results to a CSV:
`dehashapitool -e email@example.com -o results.csv`

The above will return all results for the queried email address and store it to a csv.

### Output Passwords Only:
`dehashapitool -d example.com --only-passwords`

The above will return all passwords for the queried domain, sorted alphabetically by the field query.  Example results:
```
email: bob@example.com, password: Bobert123!
email: mike@example.com, password: 2813308004
You have 40 API credits remaining
```

### Silent Output to CSV:
`dehashapitool -d example.com --only-passwords -oS results.csv`

The above will return all passwords for the queried domain, sorted alphabetically by the field query and store it to a csv while not outputting to the screen.

### Multiple Search Parameters:
`dehashapitool -d example.com -p password`

**Note: at the time of development, this search is considered an OR statement as it does not seem possible to use an AND query in the current API.**

## Advanced Usage
### Wildcards
`dehashapitool -n -e '"examp?e"' -s 10`

`dehashapitool -n -e '"examp*e"' -s 10`

The above will return 10 results utilizing the wildcard

> **Note**: As of May 2025, the wildcard search using "*" seems to be broken in the V2 API.

## Contributions
Contributions are always welcome! Please open an issue or submit a pull request.

Special thanks:
Duncan Woosley (d-woosley) - Contributions to v1 to v2 API upgrades

## Copyright
DeHashed API Tool by Heath Adams Copyright (C) 2025 TCM Security, Inc.

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see http://www.gnu.org/licenses/
