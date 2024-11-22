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

### Steps
1. Clone this repository:
```
git clone https://github.com/hmaverickadams/DeHashed-API-Tool.git
cd DeHashed-API-Tool
```

2. Install the required packages:
`pip install -r requirements.txt`

3. Change the `<email>` and `<api-key>` in the `config.txt` file to your DeHashed account email and API key.  Ensure you remove the `<>` placeholders.

## Usage
### Running the tool:
`python dehashed_parser.py --help`

### Options:
```
usage: dehashed_parser.py [-h] [-a ADDRESS] [-e EMAIL] [-H HASHED_PASSWORD] [-i IP_ADDRESS] [-n NAME] [-p PASSWORD]
                 [-P PHONE_NUMBER] [-u USERNAME] [-v VIN] [-o OUTPUT] [-oS OUTPUT_SILENTLY] [-s SIZE]
                 [--only-passwords] [--all]

Query the DeHashed API

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
  -P PHONE_NUMBER, --phone_number PHONE_NUMBER
                        Specify the phone number
  -u USERNAME, --username USERNAME
                        Specify the username
  -v VIN, --vin VIN     Specify the VIN
  -o OUTPUT, --output OUTPUT
                        Outputs to CSV. A file name is required.
  -oS OUTPUT_SILENTLY, --output_silently OUTPUT_SILENTLY
                        Outputs to CSV silently. A file name is required.
  -s SIZE, --size SIZE  Specify the size, between 1 and 10000
  --only-passwords      Return only passwords
  --all                 Save all size results, up to 30000
```

### Basic Usage:
`dehashed_parser.py -u username`

The above will return all results for the queried username.

### Output Unique Results to a CSV:
`dehashed_parser.py -e email@example.com -o results.csv`

The above will return all results for the queried email address and store it to a csv.

### Output Passwords Only:
`dehashed_parser.py -e @example.com --only-passwords`

The above will return all passwords for the queried domain, sorted alphabetically by the field query.  Example results:
```
email: bob@example.com, password: Bobert123!
email: mike@example.com, password: 2813308004
You have 40 API credits remaining
```

### Silent Output to CSV:
`dehashed_parser.py -e @example.com --only-passwords -oS results.csv`

The above will return all passwords for the queried domain, sorted alphabetically by the field query and store it to a csv while not outputting to the screen.

### Multiple Search Parameters:
`dehashed_parser.py -e @example.com -p password`

**Note: at the time of development, this search is considered an OR statement as it does not seem possible to use an AND query in the current API.**

## Advanced Usage
### OR Searches on a Single Field
`dehashed_parser.py -e "(email.com example.com)"`

The above will return results for both `email.com` and `example.com` domains

### Exact Phrases
`dehashed_parser.py -n '"Bob Ross"'`

The above will return results for the exact name of "Bob Ross".

### Wildcards
`dehashed_parser.py -n -e '"examp?e"' -s 10`

`dehashed_parser.py -n -e '"examp*e"' -s 10`

The above will return 10 results utilizing the wildcard

## Contributions
Contributions are always welcome! Please open an issue or submit a pull request.

## Copyright
DeHashed API Tool by Heath Adams Copyright (C) 2023 TCM Security, Inc.

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see http://www.gnu.org/licenses/
