import argparse
import requests
import csv
import importlib.resources
from time import sleep
import math

GENERAL_SEARCH_URL = "https://api.dehashed.com/v2/search"
PASSWORD_SEARCH_URL = "https://api.dehashed.com/v2/search-password"

# Print colors ANSI escape codes
BLUE = "\033[94m"
RED = "\033[91m"
GREY = "\033[90m"
RESET = "\033[0m"

def build_query(args):
    queries = []
    wildcard = False
    for key, value in vars(args).items():
        if key in ['address', 'email', 'hashed_password', 'ip_address', 'name', 'password', 'phone', 'username', 'vin', 'domain']:                    
            if value:
                if key == 'email':
                    # Regexing/Wildcarding emails requires that you split the query into email and domain.
                    if check_wildcard(value) or args.regex:
                        email, domain = value.split("@")
                        queries.append(f"email:{email}@{domain}")
                        queries.append(f"domain:{domain}")
                        if not args.regex:
                            wildcard = True
                        if not args.regex and "*" in value:  # At the time of writing (MAy 2025) searches using "*" seems to be broken
                            print(f"  {RED}[!] Searching using \"*\" seems to be broken in the Dehashed API side (as of May 2025). Use \"?\" instead of single character wildcards{RESET}") 
                            while True:
                                proceed = input("    [-] Would you like to continue with the request (y/n): ")
                                if proceed.lower() == "y" or proceed.lower()== "yes":
                                    break
                                if proceed.lower() == "n" or proceed.lower()== "no":
                                    exit()
                        continue

                if not args.regex:
                    if check_wildcard(value):
                        wildcard = True
                
                if key == 'domain':
                    queries.append(f"{key}:{value}")  # Domains will not except searches in quotes
                    continue

                queries.append(f"{key}:\"{value}\"")
    
    return "&".join(queries), wildcard

def check_wildcard(query_string):
    # Use ? to replace a single character, and * for multiple characters (Cannot be used along with Regex search)
    if "?" in query_string or "*" in query_string:
        return True

def v2_search(query: str, page: int, size: int, wildcard: bool, regex: bool, de_dupe: bool, api_key: str) -> dict:
    res = requests.post(GENERAL_SEARCH_URL, json={
        "query": query,
        "page": page,
        "size": size,
        "wildcard": wildcard,
        "regex": regex,
        "de_dupe": de_dupe,
    }, headers={
        "Content-Type": "application/json",
        "DeHashed-Api-Key": api_key,
    })
    return res

def flatten_list(input_list):
    if type(input_list) != list:
        return input_list
    if len(input_list) == 1:
        return input_list[0]
    return ",".join(input_list)

def unique_password_results(data):
    seen = set()
    unique_results = []
    for entry in data:
        identifier = flatten_list(entry.get('email', '')).lower(), flatten_list(entry.get('password', ''))
        if identifier not in seen:
            seen.add(identifier)
            unique_results.append(entry)
    return unique_results

def load_args():
    parser = argparse.ArgumentParser(description="Query the Dehashed API", 
                                     epilog="Usage examples:\n"
                                            "  dat --key <API_KEY> --store-creds\n"
                                            "  dehashapitool -u username\n"
                                            "  dehashapitool -e email@example.com --output results.csv\n"
                                            "  dat -d example.com --only-passwords\n"
                                            "  dat -i 192.168.0.1 -s 100 -de jdoe@example.com --key",
                                     formatter_class=argparse.RawTextHelpFormatter)

    # Required arguments
    parser.add_argument('-a', '--address', help="Specify the address")
    parser.add_argument('-e', '--email', help="Specify the email")
    parser.add_argument('-H', '--hashed_password', help="Specify the hashed password")
    parser.add_argument('-i', '--ip_address', help="Specify the IP address")
    parser.add_argument('-n', '--name', help="Specify the name")
    parser.add_argument('-p', '--password', help="Specify the password")
    parser.add_argument('-P', '--phone', help="Specify the phone number")
    parser.add_argument('-u', '--username', help="Specify the username")
    parser.add_argument('-v', '--vin', help="Specify the VIN")
    parser.add_argument('-d', '--domain', help="Specify the domain")

    # Optional arguments
    parser.add_argument('-o', '--output', help="Outputs to CSV. A file name is required.")
    parser.add_argument('-oS', '--output_silently', help="Outputs to CSV silently. A file name is required.")
    parser.add_argument('-s', '--size', type=int, default=10000, help="Specify the size, between 1 and 10000")
    parser.add_argument('--only-passwords', action="store_true", help="Return only passwords")
    parser.add_argument('--regex', action="store_true", help="Use regex search instead of string (seems to be broken as of May 2025)")

    # Dehashed API credential arguments
    api_group = parser.add_argument_group('API Arguments', 'Arguments related to Dehashed API credentials')
    api_group.add_argument(
        '--key',
        '--dehashed-key',
        dest="dehashed_key",
        nargs='?',
        const=True,
        help='Dehashed API key (overrides config.txt value)'
        )
    api_group.add_argument(
        '--store-key',
        dest="store_key",
        action="store_true",
        help="Stored the Dehashed API key in cleartext in the config.txt file (overrides previous config.txt values)"
        )

    args = parser.parse_args()

    # Prompt for Dehashed API key if not passed
    if args.dehashed_key is True:
        args.dehashed_key = input("DeHashed API Key: ")

    # Read from config file
    with importlib.resources.open_text('dehashapitool', 'config.txt') as file:
        dehashed_key = file.read().splitlines()[0]
        if not args.dehashed_key:
            if dehashed_key == "<api-key>":
                args.dehashed_key = input("DeHashed API Key: ")
            else:
                args.dehashed_key = dehashed_key

    # Write to config file
    if args.store_key:
        with importlib.resources.path('dehashapitool', 'config.txt') as config_path:
            with open(config_path, 'w') as file:
                file.write(f"{args.dehashed_key}\n")

    # Check that at least one search criteria argument is provided
    search_criteria = ['username', 'email', 'hashed_password', 'ip_address', 'vin', 'name', 'address', 'phone', 'password', 'domain']
    if not any(getattr(args, criteria) for criteria in search_criteria):
        if args.store_key:
            exit()  # Exit if only the stored creds are provided
        parser.error("[!] At least one search criteria argument is required.")

    if not 1 <= args.size <= 10000:
        parser.error("[!] Size value should be between 1 and 10000.")
        exit()
    
    return args

def recursive_search(query: str, size: int, wildcard: bool, regex: bool, api_key: str):
    entries = []
    balance = 0
    total = 0
    page_num = 0
    unlimited_calls = False
    while True:
        page_num += 1
        response = v2_search(
            query=query,
            page=page_num,
            size=size,
            wildcard=wildcard,
            regex=regex,
            de_dupe=False,
            api_key=api_key
            )
        
        if response.status_code != 200:
            print(f"{RED}[!] Error in API call!{RESET}")
            print(f"  {GREY}[-] HTTP Response Code: {response.status_code}{RESET}")
            print(f"  {GREY}[-] Response: {response.text}{RESET}")
            exit() 

        # Parse results
        try:
            data = response.json()
            balance = data['balance']
            total = data['total']
            entries = entries + data['entries']
        except ValueError:
            print(f"{RED}[!] Unexpected API response format.{RESET}")
            print(f"  {GREY}[-] Data: {data}{RESET}")  # This will print out the full API response to help you debug.
            exit()

        # Don't loop again if there is no more data on other pages
        if not total > (size * page_num):
            break
        if (size * page_num) >= 10000:
            print(f"  {RED}[!] Maximum pagination depth hit (10,000). Saving results as is...{RESET}")
            break

        # Sanity check calls to prevent burning all you API keys
        if not unlimited_calls and (total / size) > 25:
            api_calls = math.ceil(total / size)
            while True:
                proceed = input(f"  {RED}[!] You are about to make {api_calls} API calls. Are you sure you want to continue? (y/n): {RESET}")
                if proceed.lower() == "y" or proceed.lower()== "yes":
                    unlimited_calls = True
                    break
                if proceed.lower() == "n" or proceed.lower()== "no":
                    exit()

        # Avoid breaking DeHashed ratelimit
        sleep(0.1)

    return balance, entries

def main():
    args = load_args()
    query, wildcard = build_query(args)
    balance, entries = recursive_search(
        query=query,
        size=args.size,
        wildcard=wildcard,
        regex=args.regex,
        api_key=args.dehashed_key
        )
    
    if not entries:
        print(f"\n{GREY}[-] The search returned no results{RESET}")
        return

    sorted_keys = sorted(['email', 'ip_address', 'username', 'password', 'hashed_password', 'hash_type', 'name', 'vin', 'address', 'phone', 'domain'])

    primary_key = next(key for key, value in vars(args).items() if value and key in ['address', 'email', 'hashed_password', 'ip_address', 'name', 'password', 'phone', 'username', 'vin', 'domain'])

    unique_results = unique_password_results(entries)
    unique_results.sort(key=lambda x: flatten_list(x.get(primary_key, "")).lower())

    if args.only_passwords and not args.output_silently:
        for entry in unique_results:
            if primary_key == "domain":
                identifier_res = entry.get("email", '')
                primary_key = "email"
            else:
                identifier_res = entry.get(primary_key, '')
            password_res = entry.get('password', '')
            if identifier_res and password_res:
                print(f"  {BLUE}[{identifier_res}]{RESET}: {password_res}")

    elif not args.output_silently:
        for key in sorted_keys:
            values = list(set([flatten_list(entry[key]).lower() for entry in entries if key in entry and entry[key]]))
            if values:
                values.sort()
                print(f"\n  {BLUE}[{key}s]{RESET}: {', '.join(values)}")

    if not args.output_silently:
        print(f"\n{GREY}[-] You have {balance} API credits remaining.{RESET}")

    if args.output or args.output_silently:
        all_keys = set()
        for entry in entries:
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
                for entry in sorted(entries, key=lambda x: flatten_list(x.get(primary_key, "")).lower()):
                    writer.writerow({k: flatten_list(entry[k]) for k in sorted_all_keys if k in entry and entry[k] and entry[k] != "null"})

    if args.output_silently:
        print(f"\n{GREY}[-] Results returned and saved in {args.output_silently}{RESET}")
        print(f"{GREY}[-] You have {balance} API credits remaining{RESET}")
            
if __name__ == "__main__":
    main()
