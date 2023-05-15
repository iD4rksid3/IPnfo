#!/usr/bin/env python3
# coding:utf-8
"""
  Author:   --<Mayed alm @id4rksid3>
  Purpose: IPnfo Securitytrail's IP information 
  Created: 01/22/22
"""

import requests
import configparser
from colorama import init, Fore

init(autoreset=True)

def securitytrails_conf():
    config = configparser.ConfigParser()
    config.read("config_api.ini")
    securitytrails_api_key = config["API_KEY"][
        "securitytrails"
    ]  # Edit config file with your shodan API key.
    securitytrails_api_key = securitytrails_api_key.replace(" ", "")
    if securitytrails_api_key == "":
        securitytrails_api_key = None
    return securitytrails_api_key


def securitytrails_api_domain(host):
    if host == '-':
        return '-'
    st_api_key = securitytrails_conf()
    filtered_api = {}
    print(
        Fore.GREEN
        + "[i] Fetching Security Trail's data: "
        + Fore.MAGENTA
        + host
    )    
    st_api_domain = requests.get(
        f"https://api.securitytrails.com/v1/domain/{host}",
        headers={"Accept": "application/json", "apikey": st_api_key},
    ).json()
    st_api_subdomain = requests.get(
        f"https://api.securitytrails.com/v1/domain/{host}/subdomains",
        headers={"Accept": "application/json", "apikey": st_api_key},
    ).json()
    st_api_history = requests.get(
        f"https://api.securitytrails.com/v1/history/{host}/dns/a",
        headers={"Accept": "application/json", "apikey": st_api_key},
    ).json()
    total_result = {**st_api_domain, **st_api_subdomain, **st_api_history}
    for key in total_result.keys():
        if key == "current_dns":
            filtered_api["current_dns"] = total_result["current_dns"]["a"]
        elif key == "subdomains":
            filtered_api["subdomains"] = total_result["subdomains"]
        elif key == "records":
            filtered_api["history"] = total_result["records"]
        else:
            pass
    return filtered_api
