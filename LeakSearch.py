import os
import json
import urllib3
import requests
import argparse
from tabulate import tabulate
from neotermcolor import colored
from requests import ConnectionError
urllib3.disable_warnings()

banner = """
  _               _     ____                      _     
 | |    ___  __ _| | __/ ___|  ___  __ _ _ __ ___| |__  
 | |   / _ \/ _` | |/ /\___ \ / _ \/ _` | '__/ __| '_ \ 
 | |__|  __/ (_| |   <  ___) |  __/ (_| | | | (__| | | |
 |_____\___|\__,_|_|\_\|____/ \___|\__,_|_|  \___|_| |_|"""

banner2 = """                                               
  ------------------- by @JoelGMSec -------------------
  """

def find_leaks_proxynova(email, proxy, number):
    url = f"https://api.proxynova.com/comb?query={email}"
    headers = {'User-Agent': 'curl'}
    session = requests.session()

    if proxy:
        session.proxies = {'http': proxy, 'https': proxy}

    try:
        response = session.get(url, headers=headers, verify=False)

        if response.status_code == 200:
            data = response.json()
            total_results = data.get("count", 0)
            print(colored(f"[*] Found {total_results} different records in database", "magenta"))

            lines = data.get("lines", [])[:number]
            return lines
        else:
            print(colored(f"[!] Failed to fetch results from ProxyNova. Status code: {response.status_code}", "red"))
            return []
    except requests.RequestException as e:
        print(colored(f"[!] Error fetching data from ProxyNova: {e}", "red"))
        return []

def find_leaks_local_db(database, keyword, number):
    if not os.path.exists(database):
        print(colored(f"[!] Local database file not found: {database}", "red"))
        exit(-1)

    try:
        with open(database, 'r') as file:
            lines = file.readlines()

        results = [line.strip() for line in lines if keyword.lower() in line.lower()]
        print(colored(f"[*] Found {len(results)} matching records in local database", "magenta"))

        return results[:number] if number is not None else results
    except Exception as e:
        print(colored(f"[!] Error reading local database: {e}", "red"))
        exit(-1)

def find_cracked_hashes(cracked_file, keyword):
    if not os.path.exists(cracked_file):
        print(colored(f"[!] Cracked password file not found: {cracked_file}", "red"))
        exit(-1)

    try:
        with open(cracked_file, 'r') as file:
            lines = file.readlines()

        results = [line.strip() for line in lines if keyword.lower() in line.lower()]
        print(colored(f"[*] Found {len(results)} matching cracked passwords", "magenta"))

        return results
    except Exception as e:
        print(colored(f"[!] Error reading cracked password file: {e}", "red"))
        exit(-1)

def main(database, keyword, output=None, proxy=None, number=20, cracked_file=None):
    print(colored(f"[>] Searching for {keyword} leaks in {database}...", "yellow"))

    results = []
    if database.lower() == "proxynova":
        results = find_leaks_proxynova(keyword.strip(), proxy, number)
    else:
        results = find_leaks_local_db(database.strip(), keyword.strip(), number)

    if cracked_file:
        cracked_results = find_cracked_hashes(cracked_file, keyword)
        results.extend(cracked_results)

    if not results:
        print(colored(f"[!] No leaks found in {database}!", "red"))
    else:
        print_results(results, output)

def print_results(results, output):
    headers = ["Username@Domain", "Password"]
    table_data = []

    for line in results:
        parts = line.split(":")
        if len(parts) == 2:
            username_domain, password = parts
            table_data.append([username_domain, password])

    if output:
        try:
            if output.endswith('.json'):
                with open(output, 'w') as json_file:
                    json.dump({"lines": results}, json_file, indent=2)
                print(colored(f"[+] Data saved successfully in {output}!", "green"))
            else:
                with open(output, 'w') as txt_file:
                    txt_file.write(tabulate(table_data, headers, showindex="never"))
                print(colored(f"[+] Data saved successfully in {output}!", "green"))
        except IOError as e:
            print(colored(f"[!] Error saving data to {output}: {e}", "red"))
    else:
        print(tabulate(table_data, headers, showindex="never"))
        print(colored("[+] Done!", "green"))

if __name__ == '__main__':
    print(colored(banner, "blue"))
    print(colored(banner2, "green"))

    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--database", default="ProxyNova", help="Database used for the search (ProxyNova or LocalFile)")
    parser.add_argument("-k", "--keyword", required=True, help="Keyword (user/domain/pass) to search for leaks in the DB")
    parser.add_argument("-n", "--number", type=int, default=20, help="Number of results to show (default is 20)")
    parser.add_argument("-o", "--output", help="Save the results as json or txt into a file")
    parser.add_argument("-p", "--proxy", help="Set HTTP/S proxy (like http://localhost:8080)")
    parser.add_argument("-c", "--cracked-file", help="File containing cracked passwords to search")
    args = parser.parse_args()

    try:
        main(args.database, args.keyword, args.output, args.proxy, args.number, args.cracked_file)
    except ConnectionError:
        print(colored("[!] Can't connect to service! Check your internet connection!", "red"))
    except KeyboardInterrupt:
        print(colored("\n[!] Exiting..", "red"))
        exit(-1)
    except Exception as e:
        print(colored(f"[!] Error: {e}", "red"))
