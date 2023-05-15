# IPnfo v1.0

**Author:** Mayed alm @id4rksid3

IPnfo is a Python script designed to passively fetch and aggregate information related to a domain or an IP address. It uses multiple APIs including VirusTotal, Shodan, SecurityTrails, and AlienVault's OTX to retrieve this data.

## Features

1. Supports both IP addresses and domain names.
2. Fetches data like certificate information, domain resolution history, and IP information.
3. Concurrently fetches data from different sources to speed up the process.
4. Writes data to a JSON file for further analysis.

## Prerequisites

1. Python 3.7 or later.
2. Python libraries: `re`, `sys`, `json`, `configparser`, `concurrent.futures`, `colorama`, `multiprocessing`.

## Installation

Clone the repository:

git clone https://github.com/id4rksid3/ipnfo.git
cd ipnfo

Install required Python libraries:

pip install -r requirements.txt

## Configuration

API keys for VirusTotal, Shodan, SecurityTrails, and AlienVault's OTX are required. These keys should be added to the `config_api.ini` file in the following format:

[API_KEY]
securitytrails = YOUR_SECURITYTRAILS_API_KEY
virus_total = YOUR_VIRUSTOTAL_API_KEY
shodan = YOUR_SHODAN_API_KEY
otx = YOUR_ALIENVAULT_OTX_API_KEY

If the configuration file is not found, the script will automatically generate one. Simply edit the created file with your API keys and run IPnfo again.

## Usage

python3 ipnfo.py <ip_address or domain_name>

The script will output information fetched from the APIs into a JSON file named "Resolved-<input>.json".

## Note

IPnfo is designed to perform passive information gathering. It should be used responsibly and in adherence to all applicable laws and regulations.

## Contribution

Feel free to contribute to the project by creating issues, fixing bugs, or suggesting enhancements via pull requests.

## License

IPnfo is licensed under the MIT License. See `LICENSE` for more information.
