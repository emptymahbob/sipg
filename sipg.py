import colorama
import requests
import ipaddress
import sys
import json

colorama.init()

# Constants
CONFIG_FILE = 'config.json'

# Function to load Shodan API key from the configuration file
def load_api_key():
    try:
        with open(CONFIG_FILE, 'r') as config_file:
            config_data = json.load(config_file)
            return config_data.get('api_key', None)
    except FileNotFoundError:
        return None

# Function to save Shodan API key to the configuration file
def save_api_key(api_key):
    config_data = {'api_key': api_key}
    with open(CONFIG_FILE, 'w') as config_file:
        json.dump(config_data, config_file)

# Function to introduce delay based on the number of IPs printed
def introduce_delay(ip_count, delay_interval=5, results_per_delay=1000):
    if ip_count % results_per_delay == 0 and ip_count > 0:
        delay_seconds = delay_interval * (ip_count // results_per_delay)
        time.sleep(delay_seconds)

# Function to display help information
def display_help():
    help_message = """
Usage: python sipg.py -q "your-search-query" [OPTIONS]

Options:
  -q, --query         Specify the search query for Shodan.
  -h, --help          Display this help message.
  -o, --output        Save the list of IPs to a text file.

Common Search Query Examples:
  python sipg.py -q "ssl:\\"Uber Technologies Inc\\""
  python sipg.py -q "ssl:\\"Uber Technologies Inc\\" http.status:200"
  python sipg.py -q "ssl:\\"Uber Technologies Inc\\" -http.status:\\"Invalid URL\\""
  python sipg.py -q "Ssl.cert.subject.CN:\\"*.uber.com\\""
"""
    print(help_message)
    sys.exit(0)

# Banner
banner = (
    colorama.Fore.RED + "  ______           " +
    colorama.Fore.YELLOW + "_______ " +
    colorama.Fore.RED + " _______         " +
    colorama.Fore.YELLOW + "______     \n" +
    colorama.Fore.RED + " /      \         " +
    colorama.Fore.YELLOW + "/      /" +
    colorama.Fore.RED + " /       \       " +
    colorama.Fore.YELLOW + "/      \    \n" +
    colorama.Fore.RED + "/$$$$$$$ |        " +
    colorama.Fore.YELLOW + "$$$$$$/" +
    colorama.Fore.RED + " $$$$$$$  |      " +
    colorama.Fore.YELLOW + "/$$$$$$  |   \n" +
    colorama.Fore.RED + "$$ \__$$/        " +
    colorama.Fore.YELLOW + "   $$ | " +
    colorama.Fore.RED + "$$ |__$$ |      " +
    colorama.Fore.YELLOW + "$$ | _$$/    \n" +
    colorama.Fore.RED + "$$      \        " +
    colorama.Fore.YELLOW + "   $$ | " +
    colorama.Fore.RED + " $$    $$/       " +
    colorama.Fore.YELLOW + "$$ |/    |   \n" +
    colorama.Fore.RED + " $$$$$$  |        " +
    colorama.Fore.YELLOW + "  $$ | " +
    colorama.Fore.RED + " $$$$$$$/        " +
    colorama.Fore.YELLOW + "$$ |$$$$ |   \n" +
    colorama.Fore.RED + "/  \__$$ |__     " +
    colorama.Fore.YELLOW + "  _$$ |_ " +
    colorama.Fore.RED + "$$ |            " +
    colorama.Fore.YELLOW + "$$ \\__$$ |__ \n" +
    colorama.Fore.RED + "$$    $$//  |  " +
    colorama.Fore.YELLOW + "   / $$   " +
    colorama.Fore.RED + "|$$ |            " +
    colorama.Fore.YELLOW + "$$    $$//  |\n" +
    colorama.Fore.RED + " $$$$$$/ $$/    " +
    colorama.Fore.YELLOW + "  $$$$$$/ " +
    colorama.Fore.RED + "$$/              " +
    colorama.Fore.YELLOW + "$$$$$$/ $$/" +
    colorama.Style.RESET_ALL + "\n"
)

print(banner)
print("\t\tMade by @emptymahbob\n")

# Command-line arguments parsing
if len(sys.argv) < 3 or sys.argv[1] != '-q':
    if '--help' in sys.argv or '-h' in sys.argv:
        display_help()
    else:
        print("Usage: python sipg.py -q \"your-search-query\" [OPTIONS]")
        sys.exit(1)

api_key = load_api_key()

# Check if API key is available
if api_key is None:
    print("Error: Shodan API key not found in the configuration file (config.json).")
    sys.exit(1)

# Initialize total_results to zero
total_results = 0

# Send a request to the Shodan API to get the first page of search results
search_query = sys.argv[2]
response = requests.get(f'https://api.shodan.io/shodan/host/search?key={api_key}&query={search_query}&page=1')

# Check if the request was successful
if response.status_code == 200:
    try:
        # Try to parse the JSON response and get the total number of results
        results = response.json()
        total_results = results['total']

        # Print out the total number of results found in Shodan search
        print(f'Total results found: {total_results}')

        # Loop through all pages of search results and print out the IPv4 addresses
        ip_count = 0
        for page in range(1, (total_results // 100) + 2):
            try:
                response = requests.get(f'https://api.shodan.io/shodan/host/search?key={api_key}&query={search_query}&page={page}')

                if response.status_code == 200:
                    results = response.json()
                    for result in results['matches']:
                        ip = result['ip_str']
                        if ipaddress.ip_address(ip).version == 4:
                            ip_count += 1
                            print(f"{ip_count}. https://{ip}")
                            introduce_delay(ip_count)
                else:
                    print(f'Request failed with status code {response.status_code}')
            except Exception as e:
                print(f'An error occurred: {e}')
    except json.decoder.JSONDecodeError:
        print("Error: Shodan API key not found in the configuration file (config.json).")
else:
    print(f'Request failed with status code {response.status_code}')

# Save the list of IPs to a text file if --output/-o flag is provided
if '--output' in sys.argv or '-o' in sys.argv:
    output_flag_index = sys.argv.index('--output') if '--output' in sys.argv else sys.argv.index('-o')
    
    if len(sys.argv) > output_flag_index + 1:
        output_file = sys.argv[output_flag_index + 1]
        with open(output_file, 'w') as file:
            for page in range(1, (total_results // 100) + 2):
                response = requests.get(f'https://api.shodan.io/shodan/host/search?key={api_key}&query={search_query}&page={page}')
                try:
                    results = response.json()
                    for result in results['matches']:
                        ip = result['ip_str']
                        if ipaddress.ip_address(ip).version == 4:
                            file.write('https://' + ip + '\n')
                except json.decoder.JSONDecodeError:
                    print("Error: Shodan API key not found in the configuration file (config.json).")

colorama.deinit()
