#!/usr/bin/env python3
# coding:utf-8
"""
  Author:   --<Mayed alm @id4rksid3>
  Purpose: IPnfo VirusTotal's IP/domain resolutions history fetch
  Created: 09/30/21
"""
import requests
import configparser
from colorama import init, Fore

init(autoreset=True)
def vt_conf():
    config = configparser.ConfigParser()
    config.read("config_api.ini")
    vt_api_key = config["API_KEY"][
        "virus_total"
    ]  # Edit config file with your virus total API key.
    vt_api_key = vt_api_key.replace(" ", "")
    if vt_api_key == "":
        vt_api_key = None
    return vt_api_key


def vt_api_ip(host):
    vt_api_key = vt_conf()
    print(
        Fore.GREEN
        + "[i] Fetching VirusTotal resolutions: "
        + Fore.MAGENTA
        + host
    )    
    try:
        vt_api = requests.get(
        f"https://www.virustotal.com/vtapi/v2/ip-address/report?apikey={vt_api_key}&ip={host}"
    ).json()
        return vt_api["resolutions"]
    except KeyError:
        return "-"
    except:
        return "VT api key error!."    


def vt_api_domain(host):
    vt_api_key = vt_conf()
    print(
        Fore.GREEN
        + "[i] Fetching VirusTotal resolutions: "
        + Fore.MAGENTA
        + host
    )      
    try:
        vt_api = requests.get(
        f"https://www.virustotal.com/vtapi/v2/domain/report?apikey={vt_api_key}&domain={host}"
    ).json()
        return vt_api["resolutions"]
    except KeyError:
        return "-"
    except Exception as err:
        return f"VT api error: {err}"
        
