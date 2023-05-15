#!/usr/bin/env python3
# coding:utf-8
"""
  Author:   --<Mayed alm @id4rksid3>
  Purpose: IPnfo simple reverse/DNS lookup
  Created: 09/30/21
"""
import socket
from colorama import init, Fore
init(autoreset=True)
def rev_lookup_addr(ip):
    #Reverse IP lookup
    try:
        print(
            Fore.GREEN
            + "[i] Performing reverse lookup: "
            + Fore.MAGENTA 
            + ip
        )        
        revers_lookup = socket.gethostbyaddr(ip)
    except socket.herror:
        print(
            Fore.RED
            + "[W] Failed to performe IP reverse lookup: "
            + Fore.MAGENTA
            + ip
        )
        revers_lookup = "-"
    return revers_lookup

def dns_lookup_host(domain):
    #DNS lookup for domain
    try:
        print(
            Fore.GREEN
            + "[i] Performing reverse lookup: "
            + Fore.MAGENTA
            + domain
        )        
        ip_lookup = socket.gethostbyname(domain)
    except socket.gaierror:
        print(Fore.RED + "[W] Failed to performe DNS lookup: " + Fore.MAGENTA + domain)
        ip_lookup = "-"
    return ip_lookup
