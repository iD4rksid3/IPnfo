#!/usr/bin/env python3
# coding:utf-8
"""
  Author:   --<Mayed alm @id4rksid3>
  Purpose:  IPnfo Threat Crowd's IP/domain resolutions history fetch
  Created: 12/22/22
"""
from OTXv2 import OTXv2
from OTXv2 import IndicatorTypes
from colorama import init, Fore
import configparser
init(autoreset=True)


def otx_conf():
    config = configparser.ConfigParser()
    config.read("config_api.ini")
    try:
        otx_api_key = config["API_KEY"][
        "otx"
        ]  # Edit config file with your alien vault OTX API key.
        otx_api_key = otx_api_key.replace(" ", "")
    except KeyError:
        otx_api_key = ""
    if otx_api_key == "":
        otx_api_key = None
    return otx_api_key

otx_api_key = otx_conf()
otx = OTXv2(otx_api_key)

def otx_api_ip(ip):
    print(
        Fore.GREEN
        + "[i] Fetching OTX resolutions: "
        + Fore.MAGENTA
        + ip
    )        
    try:
        otx_ip = otx.get_indicator_details_full(IndicatorTypes.IPv4, ip)
    except:
        print(Fore.RED
                + "[E] Not a valid IP address!"
            )        
        return 'not a valid IP address'        
    return otx_ip['passive_dns']
    
def otx_api_domain(domain):
    print(
        Fore.GREEN
        + "[i] Fetching OTX resolutions: "
        + Fore.MAGENTA
        + domain
    )        
    try:
        otx_domain = otx.get_indicator_details_full(IndicatorTypes.DOMAIN, domain)
    except:
        print(Fore.RED
                + "[E] Not a valid domain name!"
            )        
        return 'not a valid domain name'
    return otx_domain['passive_dns']