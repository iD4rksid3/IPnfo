#!/usr/bin/env python3
# coding:utf-8
"""
  Author:   --<Mayed alm @id4rksid3>
  Purpose: IPnfo Shodan's IP information 
  Created: 09/30/21
"""

import requests
import configparser
from colorama import init, Fore

init(autoreset=True)

def shodan_conf():
    config = configparser.ConfigParser()
    config.read("config_api.ini")
    shodan_api_key = config["API_KEY"][
        "shodan"
    ]  # Edit config file with your shodan API key.
    shodan_api_key = shodan_api_key.replace(" ", "")
    if shodan_api_key == "":
        shodan_api_key = None
    return shodan_api_key


def shodan_api_ip(ip_addr):
    shodan_api_key = shodan_conf()
    print(Fore.GREEN
          + "[i] Fetching Shodan's data: "
          + Fore.MAGENTA
          + ip_addr)
    try:
        shodan_api = requests.get(
        f"https://api.shodan.io/shodan/host/{ip_addr}?key={shodan_api_key}").json()
        filtered_api = {}
        for key in shodan_api.keys():
            if key == "country_name":
                filtered_api["country_name"] = shodan_api[key]
                continue
            elif key == "ip_addrnames":
                filtered_api["ip_addrnames"] = shodan_api[key]
                continue
            elif key == "org":
                filtered_api["org"] = shodan_api[key]
                continue
            elif key == "ip_addrname":
                filtered_api["ip_addrname"] = shodan_api[key]
                continue
            elif key == "data":
                filtered_api["http"] = shodan_api[key]
                continue
            elif key == "tags":
                filtered_api["tags"] = shodan_api[key]
                continue
            elif key == "port":
                filtered_api["port"] = shodan_api[key]
                continue
            elif key == "os":
                filtered_api["os"] = shodan_api[key]
                continue
            else:
                continue
        return filtered_api
    except Exception as err:
        return f"Shodan error: {err}"
