#!/usr/bin/env python3
# coding:utf-8
"""
  Author:   --<Mayed alm @id4rksid3>
  Purpose:  IPnfo cert_fetch script is used to fetch cert info from digicert's ssltools
  Created: 09/30/21
"""
import requests
from colorama import init, Fore

def cert_info(host):
    init(autoreset=True)
    try:
        print(Fore.GREEN 
              + "[i] Fetching certificate info: "
              + Fore.MAGENTA + host)
        cert_info_get = requests.post("https://ssltools.com/api/scan", data={'url':f'{host}', 
                                                                             'path':'/', 
                                                                             'port':'443', 
                                                                             'live_scan':'true'}, 
                                                                       timeout=15)
    except requests.exceptions.ReadTimeout:
        print(Fore.RED 
              + "[W] Fetching certificate request timeout: "
              + Fore.MAGENTA + host)
        return "Error: request timeout"
    try:
        cert_info_json = cert_info_get.json()
    except Exception as err:
        return f"Certificate fetch error: {err}"
    if cert_info_json["response"] == {}:
        return "-"
    san_list = cert_info_json["response"]["san_entries"]
    return san_list
