#!/usr/bin/env python3
# coding:utf-8
"""
  Author:   --<Mayed alm @id4rksid3>
  Purpose: IPnfo: script to passively fetch information of a domain or IP address.
  Created: 05/15/23
  Version: 1.0
"""

import re
import sys
import json
import configparser
from time import sleep
import multiprocessing
from colorama import init, Fore
from concurrent.futures import ThreadPoolExecutor

###IPnfo modules###
from modules.cert_fetch import cert_info

# from modules.tc_api import tc_api_ip, tc_api_domain #Threat Crowd is down..
from modules.otx_api import otx_api_ip, otx_api_domain, otx_conf
from modules.shodan_api import shodan_api_ip, shodan_conf
from modules.vt_api import vt_api_ip, vt_api_domain, vt_conf
from modules.rev_lookup import rev_lookup_addr, dns_lookup_host
from modules.securitytrails_api import securitytrails_api_domain, securitytrails_conf


class ipnfo:
    """
    script to perform passive information and history data gathering about IP address or host using mutiple APIs
    """

    banner = """

    ██╗██████╗░███╗░░██╗███████╗░█████╗░
    ██║██╔══██╗████╗░██║██╔════╝██╔══██╗
    ██║██████╔╝██╔██╗██║█████╗░░██║░░██║
    ██║██╔═══╝░██║╚████║██╔══╝░░██║░░██║
    ██║██║░░░░░██║░╚███║██║░░░░░╚█████╔╝ v1.0
    ╚═╝╚═╝░░░░░╚═╝░░╚══╝╚═╝░░░░░░╚════╝░©Mayed.alm
    [+]IPnfo: passively retrieve information and history data about IP address or host using mutiple APIs\n"""

    def __init__(self, inpt):
        # Config
        config = configparser.ConfigParser()
        try:
            self.vt_api_key = vt_conf()
            self.shodan_api_key = shodan_conf()
            self.securitytrails_api_key = securitytrails_conf()
            self.otx_api_key = otx_conf()
        except KeyError:
            config["API_KEY"] = {
                "securitytrails": "",
                "virus_total": "",
                "shodan": "",
                "otx": "",
            }
            config.write(open("config_api.ini", "w"))
            exit(
                Fore.RED
                + "[E] Configuration file not found! creating one, edit it with api keys and run IPnfo again."
            )
        init(autoreset=True)
        self.inpt = inpt
        self.reslove_func_ip(self.inpt)

    # func to performe reverse ip lookup and dns history/ ssl alt names
    def reslove_func_ip(self, inpt):
        # Check IPv4 input
        ipv4 = re.compile(
            "^(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"
        )
        match_ip = ipv4.match(inpt)
        # Check domain name input
        domain_name = re.compile(
            "^(([a-zA-Z]{1})|([a-zA-Z]{1}[a-zA-Z]{1})|([a-zA-Z]{1}[0-9]{1})|([0-9]{1}[a-zA-Z]{1})|([a-zA-Z0-9][a-zA-Z0-9-_]{1,61}[a-zA-Z0-9]))\.([a-zA-Z]{2,6}|[a-zA-Z0-9-]{2,30}\.[a-zA-Z]{2,3})$"
        )
        match_domain_name = domain_name.match(inpt)
        if match_ip is None:
            if match_domain_name is None:
                sys.exit(
                    Fore.RED
                    + "[E] Incorrect Domain name/IPv4 address: "
                    + Fore.MAGENTA
                    + inpt
                )

        # Fetching data and write it to json file
        with open("Resolved-" + inpt.replace(":", "") + ".json", "w") as file_out_json:
            print(Fore.GREEN + "[i] Running: " + Fore.MAGENTA + inpt)

            # fetching the cert info usinf digicert ssltools
            with ThreadPoolExecutor() as executor:
                cert = executor.submit(cert_info, inpt)
                sleep(0.1)
                if match_ip:
                    ip = inpt
                    # reverse IP lookup using system's DNS
                    revers_lookup = executor.submit(rev_lookup_addr, ip)
                    sleep(0.1)
                    # Using Threat Crowd's API service to fetch resolutions history
                    # threat_crowd_res = executor.submit(tc_api_ip, ip)
                    if self.otx_api_key is not None:
                        otx_res = executor.submit(otx_api_ip, ip)
                        sleep(0.1)
                    else:
                        print(
                            Fore.RED
                            + "[W] Alien Vault OTX api key not found in config file! -- SKIPPING"
                        )
                        otx_res = executor.submit(otx_conf)
                    # Check for VT API key
                    if self.vt_api_key is not None:
                        virus_total = executor.submit(vt_api_ip, ip)
                        sleep(0.1)
                    else:
                        print(
                            Fore.RED
                            + "[W] VirusTotal api key not found in config file! -- SKIPPING"
                        )
                        virus_total = executor.submit(vt_conf)
                    if self.shodan_api_key is not None:
                        # Using Shodan to fetch IP info
                        shodan = executor.submit(shodan_api_ip, ip)
                        sleep(0.1)
                    else:
                        print(
                            Fore.RED
                            + "[W] Shodan api key not found in config file! -- SKIPPING"
                        )
                        shodan = executor.submit(shodan_conf)
                    if self.securitytrails_api_key is not None:
                        sec_trails = executor.submit(
                            securitytrails_api_domain, revers_lookup.result()[0]
                        )
                        sleep(0.1)
                    else:
                        print(
                            Fore.RED
                            + "[W] Security Trails api key not found in config file! -- SKIPPING"
                        )
                        sec_trails = executor.submit(securitytrails_conf)
                    ###Writing to JSON file output###
                    ip_ = ip.replace(".", "_")
                    data = {}
                    data[ip_] = {}
                    data[ip_]["reverse_lookup"] = (revers_lookup.result(),)
                    data[ip_]["certificate_common_name"] = (cert.result(),)
                    data[ip_]["security_trails"] = (sec_trails.result(),)
                    data[ip_]["virustotal_resolutions"] = (virus_total.result(),)
                    # data[ip_]["threat_crowd_resolutions"] = (threat_crowd_res.result(),)
                    data[ip_]["otx_resolutions"] = (otx_res.result(),)
                    data[ip_]["shodan"] = (shodan.result(),)
                    json.dump(data, file_out_json, indent=4)
                    print(Fore.GREEN + "[i] Done: " + Fore.MAGENTA + ip)

                elif match_domain_name:
                    domain = inpt
                    # resolve domain to IP using system's DNS
                    dns_lookup = executor.submit(dns_lookup_host, domain)
                    sleep(0.1)
                    if self.otx_api_key is not None:
                        otx_res = executor.submit(otx_api_domain, domain)
                        sleep(0.1)
                    else:
                        print(
                            Fore.RED
                            + "[W] Alien Vault OTX api key not found in config file! -- SKIPPING"
                        )
                        otx_res = executor.submit(otx_conf)
                    if self.vt_api_key is not None:
                        virus_total = executor.submit(vt_api_domain, domain)
                        sleep(0.1)
                    else:
                        print(
                            Fore.RED
                            + "[W] VirusTotal api key not found in config file! -- SKIPPING"
                        )
                        virus_total = executor.submit(vt_conf)
                    if self.shodan_api_key is not None:
                        # Using Shodan to fetch IP info
                        shodan = executor.submit(shodan_api_ip, dns_lookup.result())
                        sleep(0.1)
                    else:
                        print(
                            Fore.RED
                            + "[W] Shodan api key not found in config file! -- SKIPPING"
                        )
                        shodan = executor.submit(shodan_conf)

                    if self.securitytrails_api_key is not None:
                        sec_trails = executor.submit(securitytrails_api_domain, domain)
                        sleep(0.1)
                    else:
                        print(
                            Fore.RED
                            + "[W] Security Trails api key not found in config file! -- SKIPPING"
                        )
                        sec_trails = executor.submit(securitytrails_conf)

                    # threat_crowd_res, threat_crowd_subd = executor.submit(tc_api_domain, domain).result()
                    # sleep(0.1)

                    ###Writing to JSON file output###
                    data = {}
                    data[domain] = {}
                    data[domain]["dns_lookup"] = (dns_lookup.result(),)
                    data[domain]["certificate_common_name"] = (cert.result(),)
                    data[domain]["security_trails"] = (sec_trails.result(),)
                    data[domain]["virustotal_resolutions"] = (virus_total.result(),)
                    # data[domain]["threat_crowd_resolutions"] = (threat_crowd_res,)
                    # data[domain]["threat_crowd_subdomains"] = (threat_crowd_subd,)
                    data[domain]["otx_resolutions"] = (otx_res.result(),)
                    data[domain]["shodan"] = (shodan.result(),)
                    json.dump(data, file_out_json, indent=4)
                    print(Fore.GREEN + "[i] Done: " + Fore.MAGENTA + domain)


if __name__ == "__main__":
    run = ipnfo
    if len(sys.argv) < 2:
        print(Fore.YELLOW + run.banner)
        sys.exit("[!] Usage:\n IPnfo.py 1.2.3.4\n IPnfo.py example.com 1.1.1.1")
    elif sys.argv[1] == "-h" or sys.argv[1] == "--help":
        print(Fore.YELLOW + run.banner)
        sys.exit("[!] Usage:\n IPnfo.py 1.2.3.4\n IPnfo.py example.com 1.1.1.1")
    elif len(sys.argv) == 2:
        print(Fore.YELLOW + run.banner)
        run(sys.argv[1])
    else:
        print(Fore.YELLOW + run.banner)
        ip_list = sys.argv[1:]
        procs = []
        for item in ip_list:
            proc = multiprocessing.Process(target=run, args=(item,))
            procs.append(proc)
            proc.start()
        for proc in procs:
            proc.join()
