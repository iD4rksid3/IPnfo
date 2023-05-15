#!/usr/bin/env python3
# coding:utf-8
"""
  Author:   --<Mayed alm @id4rksid3>
  Purpose:  IPnfo Threat Crowd's IP/domain resolutions history fetch
  Created: 09/30/21
"""
import requests
from colorama import init, Fore

init(autoreset=True)

def tc_api_ip(ip):
    threat_crowdAPI = requests.get(
        "http://www.threatcrowd.org/searchApi/v2/ip/report/", params={"ip": ip}
    )
    try:
        print(
            Fore.GREEN
            + "[i] Fetching ThreatCrowd resolutions: "
            + Fore.MAGENTA
            + ip
        )        
        threat_crowdJSON = threat_crowdAPI.json()
        threat_crowd_res = threat_crowdJSON["resolutions"]
        return threat_crowd_res
    except:
        threat_crowd_res = "-"
        print(
            Fore.RED
            + "[W] Failed to fetch resolutions from ThreatCrowd: "
            + Fore.MAGENTA
            + ip
        )
        return threat_crowd_res


def tc_api_domain(host):
    threat_crowdAPI = requests.get(
        "http://www.threatcrowd.org/searchApi/v2/domain/report/",
        params={"domain": host},
    )
    try:
        print(
            Fore.GREEN
            + "[i] Fetching ThreatCrowd resolutions: "
            + Fore.MAGENTA
            + host
        )        
        threat_crowdJSON = threat_crowdAPI.json()
        threat_crowd_res = threat_crowdJSON["resolutions"]
    except Exception as err:
        threat_crowd_res = "-"
        print(
            Fore.RED
            + f"[W] Failed to fetch reolutions from ThreatCrowd: {err}"
            + Fore.MAGENTA
            + host
        )
    try:
        threat_crowd_subd = threat_crowdJSON["subdomains"]
    except Exception as err:
        threat_crowd_subd = "-"
        print(
            Fore.RED
            + f"[W] Failed to fetch subdomains from ThreatCrowd: {err}"
            + Fore.MAGENTA
            + host
        )
    return threat_crowd_res, threat_crowd_subd
