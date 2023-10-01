#!/usr/bin/python3
# coding: utf-8

import os
import requests
import json

def get_api_key():
    try:
        key_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config", "api_key.txt")
        with open(key_file, "r") as file:
            api_key = file.read().strip()
        return api_key
    except FileNotFoundError:
        print("\nNo 'api_key.txt' File Found!.\n")
        return None
    except Exception as e:
        print("\nError while reading the api_key.txt! Check if the api key is correct.\n", str(e))
        return None

def check_vt_advanced(sha256_hash, output_file):
    api_key = get_api_key()
    url = f"https://www.virustotal.com/api/v3/files/{sha256_hash}/behaviours"
    headers = {
        "x-apikey": api_key
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        result = json.loads(response.content)
        with open(output_file, "w") as file:
            file.write(json.dumps(result, indent=4))
    else:
        with open(output_file, "w") as file:
            file.write("\tVirusTotal check failed! OR No such file available in VT.")
