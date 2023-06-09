# IPnfo

IPnfo is a Python script designed to passively fetch and aggregate information related to a domain or an IP address. It uses multiple APIs including VirusTotal, Shodan, SecurityTrails, and AlienVault's OTX to retrieve this data.

## Features

1. Supports both IP addresses and domain names.
2. Fetches data like certificate information, domain resolution history, and IP information.
3. Concurrently fetches data from different sources to speed up the process.
4. Writes data to a JSON file for further analysis.

## Prerequisites

1. Python 3.7 or later.
2. Python libraries: `requests`, `configparser`, `colorama`, `OTXv2`.

## Installation

Clone the repository:

```bash
git clone https://github.com/id4rksid3/ipnfo.git
```

Change to repository directory:
```bash
cd ipnfo
```


Install required Python libraries:
```bash
pip install -r requirements.txt
```
## Configuration

API keys for VirusTotal, Shodan, SecurityTrails, and AlienVault's OTX are required to get more information. These keys should be added to the `config_api.ini` file in the following format:

[API_KEY]

securitytrails = YOUR_SECURITYTRAILS_API_KEY

virus_total = YOUR_VIRUSTOTAL_API_KEY

shodan = YOUR_SHODAN_API_KEY

otx = YOUR_ALIENVAULT_OTX_API_KEY

If the configuration file is not found, the script will automatically generate one. Simply edit the created file with your API keys and run IPnfo again.

## Usage

```bash
python3 ipnfo.py <ip_address or domain_name>
```

The script will output information fetched from the APIs into a JSON file named `Resolved-<input>.json`.

## Sample output
```bash
{
    "example.com": {
        "dns_lookup": [
            "93.184.216.34"
        ],
        "certificate_common_name": [
            [
                "www.example.org",
                "example.net",
                "example.edu",
                "example.com",
                "example.org",
                "www.example.com",
                "www.example.edu",
                "www.example.net"
            ]
        ],
        "security_trails": [
            {
                "current_dns": {
                    "first_seen": "2018-09-10",
                    "values": [
                        {
                            "h": null,
                            "ip": "93.184.216.34",
                            "ip_count": 948,
                            "ip_organization": "MCI Communications Services, Inc. d/b/a Verizon Business"
                        }
                    ]
                },
                "subdomains": [
                    "auth",
                    "proxy",
                    "support",
                    "test1",
                    "autoconfig",
                    "your-cloud-controller",
                    "test",
                    .
                    .
                    .
                    .
                    .
                    .
  ```
## Note

IPnfo is designed to perform passive information gathering. It should be used responsibly and in adherence to all applicable laws and regulations.

## Contribution

Feel free to contribute to the project by creating issues, fixing bugs, or suggesting enhancements via pull requests.

## License

IPnfo is licensed under the MIT License. See `LICENSE` for more information.
