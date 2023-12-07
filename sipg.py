import os
import click
import requests
import ipaddress
import json

CONFIG_FILE = 'config.json'

# Load API key from config file or set it to None if not present
api_key = None
if os.path.exists(CONFIG_FILE):
    with open(CONFIG_FILE, 'r') as config_file:
        config_data = json.load(config_file)
        api_key = config_data.get('api_key')

BANNER = '''
  ______           _______  _______         ______
 /      \         /      / /       \       /      \\
/$$$$$$$ |        $$$$$$/ $$$$$$$  |      /$$$$$$  |
$$ \\__$$/           $$ |  $$ |__$$ |      $$ | _$$/
$$      \\           $$ |  $$    $$/       $$ |/    |
 $$$$$$  |          $$ |  $$$$$$$/        $$ |$$$$ |
/  \\__$$ |__       _$$ |_ $$ |            $$ \\__$$ |__
$$    $$//  |     / $$   |$$ |            $$    $$//  |
 $$$$$$/ $$/      $$$$$$/ $$/              $$$$$$/ $$/
'''

print(BANNER)
print("\t\tMade by @emptymahbob\n")


def save_api_key(api_key):
    config_data = {'api_key': api_key}
    with open(CONFIG_FILE, 'w') as config_file:
        json.dump(config_data, config_file)


def remove_api_key():
    if os.path.exists(CONFIG_FILE):
        os.remove(CONFIG_FILE)
        print("API key removed successfully.")
    else:
        print("No API key found.")


def search_and_save_results(api_key, search_query, output_file=None):
    # If an output file is provided, open it in write mode
    if output_file:
        with open(output_file, 'w') as file:
            write_to_file = True
    else:
        # If no output file is provided, print the results to the command line
        write_to_file = False

    # Send a request to the Shodan API to get the first page of search results
    response = requests.get(f'https://api.shodan.io/shodan/host/search?key={api_key}&query={search_query}')

    # Check if the request was successful
    if response.status_code == 200:
        # Parse the JSON response and get the total number of results
        results = response.json()
        total_results = results['total']

        # Print out the total number of results found in Shodan search
        print(f'Total results: {total_results}')

        # Loop through all pages of search results and print out the IPv4 addresses
        for page in range(1, (total_results // 100) + 2):
            response = requests.get(f'https://api.shodan.io/shodan/host/search?key={api_key}&query={search_query}&page={page}')
            if response.status_code == 200:
                results = response.json()
                for result in results['matches']:
                    ip = result['ip_str']
                    if ipaddress.ip_address(ip).version == 4:
                        print(ip)
                        # Write the IP address to the output file if provided
                        if write_to_file:
                            file.write(ip + '\n')
            else:
                print(f'Request failed with status code {response.status_code}')
    else:
        print(f'Request failed with status code {response.status_code}')


@click.command()
@click.option('-q','--query', required=True, help='Search query')
@click.option('--change-key', is_flag=True, help='Change the API key')
@click.option('--remove-key', is_flag=True, help='Remove the API key')
def main(query, change_key, remove_key):
    global api_key

    # If API key is not provided or is not saved in the config file, ask for it
    if not api_key:
        api_key = click.prompt('Enter your Shodan API key')

        # Save the API key to the config file
        save_api_key(api_key)

    # If the change-key option is provided, ask for a new API key and update it in the config file
    if change_key:
        new_api_key = click.prompt('Enter the new Shodan API key')
        save_api_key(new_api_key)
        print('API key updated successfully.')
        return

    # If the remove-key option is provided, remove the API key from the config file
    if remove_key:
        remove_api_key()
        return

    # Search and save results
    search_and_save_results(api_key, query)


if __name__ == "__main__":
    main()
