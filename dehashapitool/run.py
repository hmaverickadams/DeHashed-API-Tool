import argparse
import requests
import re
import json
import csv
from urllib.parse import quote
import importlib.resources

def escape_special_chars(query):
    reserved_chars = "+-=&&||><!(){}[]^\"~*?:"
    for char in reserved_chars:
        query = query.replace(char, f"\{char}")
    return quote(query, safe='')

def build_query(args):
    queries = []
    for key, value in vars(args).items():
        if key in ['address', 'email', 'hashed_password', 'ip_address', 'name', 'password', 'phone_number', 'username', 'vin']:
            if value:
                queries.append(f"{key}:{escape_special_chars(value)}")
    return "&".join(queries)

def query_api(query, size, dehashed_email, dehashed_key):
    headers = {
        'Accept': 'application/json',
    }
    response = requests.get(
        f'https://api.dehashed.com/search?query={query}&size={size}', 
        auth=(dehashed_email, dehashed_key), 
        headers=headers
    )
    return response

def unique_password_results(data):
    seen = set()
    unique_results = []
    for entry in data:
        identifier = (entry.get('email', '').lower(), entry.get('password', ''))
        if identifier not in seen:
            seen.add(identifier)
            unique_results.append(entry)
    return unique_results

def load_args():
    parser = argparse.ArgumentParser(description="Query the Dehashed API", 
                                     epilog="Usage examples:\n"
                                            "  dat -de jdoe@example.com --key --store-creds\n"
                                            "  dehashapitool -u username\n"
                                            "  dehashapitool -e email@example.com --output results.csv\n"
                                            "  dat -e @example.com --only-passwords\n"
                                            "  dat -i 192.168.0.1 -s 100 -de jdoe@example.com --key",
                                     formatter_class=argparse.RawTextHelpFormatter)

    # Required arguments
    parser.add_argument('-a', '--address', help="Specify the address")
    parser.add_argument('-e', '--email', help="Specify the email")
    parser.add_argument('-H', '--hashed_password', help="Specify the hashed password")
    parser.add_argument('-i', '--ip_address', help="Specify the IP address")
    parser.add_argument('-n', '--name', help="Specify the name")
    parser.add_argument('-p', '--password', help="Specify the password")
    parser.add_argument('-P', '--phone_number', help="Specify the phone number")
    parser.add_argument('-u', '--username', help="Specify the username")
    parser.add_argument('-v', '--vin', help="Specify the VIN")

    # Optional arguments
    parser.add_argument('-o', '--output', help="Outputs to CSV. A file name is required.")
    parser.add_argument('-oS', '--output_silently', help="Outputs to CSV silently. A file name is required.")
    parser.add_argument('-s', '--size', type=int, default=10000, help="Specify the size, between 1 and 10000")
    parser.add_argument('--only-passwords', action="store_true", help="Return only passwords")

    # Dehashed API credential arguments
    api_group = parser.add_argument_group('API Arguments', 'Arguments related to Dehashed API credentials')
    api_group.add_argument(
        '-de',
        '--dehashed-email',
        dest="dehashed_email",
        nargs='?',
        const=True,
        help='Dehashed account email address (overrides config.txt value)'
        )
    api_group.add_argument(
        '--key',
        '--dehashed-key',
        dest="dehashed_key",
        nargs='?',
        const=True,
        help='Dehashed API key (overrides config.txt value)'
        )
    api_group.add_argument(
        '--store-creds',
        dest="store_creds",
        action="store_true",
        help="Stored the Dehashed email and API key in the config.txt file (overrides previous config.txt value)"
        )

    args = parser.parse_args()

    # Prompt for Dehashed API email/key if not passed
    if args.dehashed_email is True:
        args.dehashed_email = input("DeHashed Email Address: ")
    if args.dehashed_key is True:
        args.dehashed_key = input("DeHashed API Key: ")

    # Read from config file
    with importlib.resources.open_text('dehashapitool', 'config.txt') as file:
        dehashed_email, dehashed_key = file.read().splitlines()
        if not args.dehashed_email:
            args.dehashed_email = dehashed_email
        if not args.dehashed_key:
            args.dehashed_key = dehashed_key

    # Write to config file
    if args.store_creds:
        with importlib.resources.path('dehashapitool', 'config.txt') as config_path:
            with open(config_path, 'w') as file:
                file.write(f"{args.dehashed_email}\n")
                file.write(f"{args.dehashed_key}\n")

    return args

def main():
    args = load_args()

    # Check that at least one search criteria argument is provided
    search_criteria = ['username', 'email', 'hashed_password', 'ip_address', 'vin', 'name', 'address', 'phone_number', 'password']
    if not any(getattr(args, criteria) for criteria in search_criteria):
        parser.error("At least one search criteria argument is required.")

    if not 1 <= args.size <= 10000:
        print("Size value should be between 1 and 10000.")
        return
    
    query = build_query(args)
    response = query_api(query, args.size, args.dehashed_email, args.dehashed_key)
    
    if response.status_code != 200:
        print(f"HTTP Response Code: {response.status_code}")
        print(response.text)
        return

    data = response.json()

    # Check if "entries" key is in the data
    if "entries" not in data:
        print("Unexpected API response format.")
        print(data)  # This will print out the full API response to help you debug.
        return

    if not data["entries"]:
        print("The search returned no results")
        return

    sorted_keys = sorted(['email', 'ip_address', 'username', 'password', 'hashed_password', 'hash_type', 'name', 'vin', 'address', 'phone'])

    primary_key = next(key for key, value in vars(args).items() if value and key in ['address', 'email', 'hashed_password', 'ip_address', 'name', 'password', 'phone_number', 'username', 'vin'])

    unique_results = unique_password_results(data["entries"])
    unique_results.sort(key=lambda x: x.get(primary_key, "").lower())

    if args.only_passwords and not args.output_silently:
        for entry in unique_results:
            identifier_res = entry.get(primary_key, '')
            password_res = entry.get('password', '')
            if identifier_res and password_res:
                print(f"{primary_key}: {identifier_res}, password: {password_res}")

    elif not args.output_silently:
        for key in sorted_keys:
            values = list(set([entry[key].lower() for entry in data["entries"] if key in entry and entry[key]]))
            if values:
                values.sort()
                print(f"{key}s: {', '.join(values)}")

    if not args.output_silently:
        print(f"You have {data['balance']} API credits remaining")

    if args.output or args.output_silently:
        all_keys = set()
        for entry in data["entries"]:
            all_keys.update([k for k, v in entry.items() if v and v != "null"])

        # Exclude 'database' and 'id'
        all_keys -= {'database', 'id'}
        sorted_all_keys = [primary_key] + [k for k in sorted(list(all_keys)) if k != primary_key]

        target_file = args.output if args.output else args.output_silently
        with open(target_file, 'w', newline='') as csvfile:
            if args.only_passwords:
                fieldnames = [primary_key, 'password']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                for entry in unique_results:
                    if entry.get('password'):
                        writer.writerow({k: entry[k] for k in fieldnames if k in entry and entry[k] and entry[k] != "null"})
            else:
                writer = csv.DictWriter(csvfile, fieldnames=sorted_all_keys)
                writer.writeheader()
                for entry in sorted(data["entries"], key=lambda x: x.get(primary_key, "").lower()):
                    writer.writerow({k: entry[k] for k in sorted_all_keys if k in entry and entry[k] and entry[k] != "null"})

    if args.output_silently:
        print(f"Results returned and saved in {args.output_silently}")
        print(f"You have {data['balance']} API credits remaining")
            
if __name__ == "__main__":
    main()
