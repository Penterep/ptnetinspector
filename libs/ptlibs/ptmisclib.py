from hashlib import sha256
import datetime
import os
import pickle
import signal
import sys
import tempfile
import typing
import re

import requests
from requests_toolbelt.utils import dump

from ptlibs import ptdefs
from ptlibs.ptprinthelper import out_if, ptprint


def signal_handler(sig, frame):
    ptprint(f"\r", clear_to_eol=True)
    ptprint( out_if(f"{ptdefs.colors['ERROR']}Script terminated{ptdefs.colors['TEXT']}", "ERROR"), clear_to_eol=True)
    sys.exit(0)
signal.signal(signal.SIGINT, signal_handler)


def read_file(file: str) -> list[str]:
    with open(file, "r") as f:
        domain_list = [line.strip("\n") for line in f]
        return domain_list


def pairs(pair):
    if len(pair.split(":")) == 2:
        return pair
    else:
         raise ValueError('Not a pair')


def get_wordlist(file_handler, begin_with=""):
    while True:
        data = file_handler.readline().strip()
        if not data:
            break
        if data.startswith(begin_with):
            yield data


def time2str(time):
    return str(str(datetime.timedelta(seconds=time))).split(".")[0]


def save_object(obj: dict,  filename) -> None:
    with open(os.path.join(tempfile.gettempdir(), "pentereptools", filename), "wb") as output_file:
        pickle.dump(obj, output_file, pickle.HIGHEST_PROTOCOL)


def load_object(filename) -> object:
    with open(os.path.join(tempfile.gettempdir(), "pentereptools", filename), "rb") as input_file:
        return pickle.load(input_file)


def exists_temp(filename: str) -> bool:
    """Checks whether a file exists in tmp and is created in the last day

    Args:
        filename (str): name of the file

    Returns:
        bool: True if the file exists and is created in the last day
    """

    #check if file exists in tmp
    if not os.path.isfile(os.path.join(tempfile.gettempdir(), "pentereptools", filename)):
        return False

    #check if file is created in the last day
    file_older_than_day = get_file_modification_age(filename).days > 1
    if file_older_than_day:
        os.remove(os.path.join(tempfile.gettempdir(), "pentereptools", filename))
        return False
    else:
        return True


def get_file_modification_age(filename: str) -> datetime.timedelta:
    return (datetime.datetime.now() - datetime.datetime.fromtimestamp(os.path.getmtime(os.path.join(tempfile.gettempdir(), "pentereptools", filename))))


def get_temp_filename_from_url(url: str, method: str) -> str:
    input_bytes = (url + method).encode()
    return sha256(input_bytes).hexdigest()


def get_response_data_dump(response: requests.models.Response) -> dict:
    """Returns a dictionary containing dump of response data from provided response object

    Args:
        response (requests.models.Response): response object

    Returns:
        dict: {"request_data": str, "response_data": str}
    """
    try:
        response_dump = dump.dump_response(response, request_prefix="req:", response_prefix="res:").decode("utf-8", "ignore")
        req = re.sub("req:", "", '\n'.join(re.findall(r"(req:.*)", response_dump, re.MULTILINE)))
        res = re.sub("^res:", "", ''.join(re.search(r"(res:(.|\n)*)", response_dump, re.MULTILINE).groups()), flags=re.MULTILINE)[:-1]
        return {"request": req, "response": res}
    except Exception as e:
        print("type of error:", e)
        return {"request": "error", "response": "error"}


def load_url_from_web_or_temp(url: str, method: str, headers: dict, proxies: dict, allow_redirects: bool, verify: bool , timeout: int, dump_response: bool = False) -> requests.Response:
    """Gets http response from url. If the response is already saved in a temp file, it will be loaded from there.
       If response is not present, it will be requested from URL and saved to temp folder.

    Args:
        url           (str)  : request url
        method        (str)  : request method
        proxies       (dict) : request proxies
        headers       (dict) : request headers
        verify        (bool) : verify requests
        dump_response (bool) : if truthy, this function returns a tuple containing [ response, response_dump ]

    Returns:
        Default:
            requests.models.Response: response
        With dump_response:
            tuple: [ response: requests.models.Response, {request_dump: str, response_dump: str} ]
    """

    # Create penterep dir in tmp if not present
    if not os.path.exists(os.path.join(tempfile.gettempdir(), "pentereptools")):
        os.makedirs(os.path.join(tempfile.gettempdir(), "pentereptools"))

    filename = get_temp_filename_from_url(url, method)
    if exists_temp(filename):
        pickled_object = load_object(filename)
        if dump_response:
            return (pickled_object["response"], pickled_object["response_dump"])
        return pickled_object["response"]
    else:
        try:
            response = requests.request(method, url, proxies=proxies, allow_redirects=allow_redirects, headers=headers, verify=verify, timeout=timeout)
        except requests.exceptions.RequestException as error:
            raise error
        response_dump = get_response_data_dump(response)
        pickle_object = {"response": response, "response_dump": response_dump}
        save_object(pickle_object, filename)
        if dump_response:
            return (response, response_dump)
        return response
