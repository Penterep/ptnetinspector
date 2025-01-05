import random
import re
import sys
import typing
import ipaddress

import requests

from ptlibs import ptdefs
from ptlibs.ptprinthelper import ptprint, out_if


def randomIP() -> str:
    ip = ''
    ip += str(random.randint(1, 255))   # first octet
    for i in range(3):
        ip += '.'   # dot between octets
        ip += str(random.randint(0, 255))   # octet 2-4
    return ip


def randomPort() -> int:
    port = random.randint(1, 65535)
    return port


def check_connectivity(proxies: dict) -> None:
    try:
        requests.request("GET", "https://www.google.com", proxies=proxies, verify=False, allow_redirects=True)
    except:
        ptprint( out_if(f"{ptdefs.colors['ERROR']}Missing net connectivity{ptdefs.colors['TEXT']}", "ERROR"))
        sys.exit(1)


def is_valid_ip_address(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def check_url_availability(url, proxies={}) -> None:
    try:
        requests.request("GET", url, proxies=proxies, verify=False, allow_redirects=False)
    except Exception as e:
        ptprint( out_if(f"{ptdefs.colors['ERROR']}URL is not available: {e}{ptdefs.colors['TEXT']}", "ERROR"))
        sys.exit(0)


def get_request_headers(args) -> dict:
    request_headers = {}
    if args.user_agent:
        request_headers.update({"User-Agent": args.user_agent})
    if args.cookie:
        if isinstance(args.cookie, list):
            request_headers.update({"Cookie": '; '.join(args.cookie)})
        elif isinstance(args.cookie, str):
            request_headers.update({"Cookie": args.cookie})
    if args.headers:
        for header in args.headers:
            request_headers.update({header.split(":")[0]: header.split(":")[1]})
    return request_headers


def add_slash_to_end_url(url: str) -> str:
    if url.find("*") == -1 and not url.endswith("/"):
        return url+"/"
    else:
        return url


def remove_slash_from_end_url(url: str) -> str:
    if url.find("*") == -1 and url.endswith("/"):
        return url[:-1]
    else:
        return url
