#!/usr/bin/python3
# coding: utf-8

import os
import requests
import datetime

def get_api_key():
    try:
        key_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config", "api_key.txt")
        with open(key_file, "r") as file:
            api_key = file.read().strip()
        return api_key
    except FileNotFoundError as e:
        print(f"No 'api_key.txt' File Found!")
        return None
    except Exception as e:
        print(f"\nError while reading the api_key.txt! Check if the api key is correct.\n")
        return None

def check_virustotal(sha256_hash, output_file):
    api_key = get_api_key()
    url = f"https://www.virustotal.com/api/v3/files/{sha256_hash}"
    headers = {
        "x-apikey": api_key
    }

    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        result = response.json()
        with open(output_file, "w") as file:
            file.write("++++++++++++++++++++++++\n") 
            file.write("VirusTotal Check Results\n")
            file.write("++++++++++++++++++++++++\n\n") 
            file.write(f"SHA256: {result['data']['attributes']['sha256']}\n")
            # Getting SSDEEP value
            if "ssdeep" in result['data']['attributes']:
                ssdeep = result['data']['attributes']['ssdeep']
                file.write(f"SSDEEP: {ssdeep}\n")
            
            # Getting TLSH value
            if "tlsh" in result['data']['attributes']:
                tlsh = result['data']['attributes']['tlsh']
                file.write(f"TLSH:   {tlsh}\n")
            
            # Getting Vhash value
            if "vhash" in result['data']['attributes']:
                vhash = result['data']['attributes']['vhash']
                file.write(f"Vhash:  {vhash}\n")
            
            # Getting Threat Label
            if "suggested_threat_label" in result['data']['attributes']['popular_threat_classification']:
                suggested_threat_label = result['data']['attributes']['popular_threat_classification']['suggested_threat_label']
                file.write(f"\nPopular Threat Label:     {suggested_threat_label}")
            
            # Getting Threat Category
            if "popular_threat_category" in result['data']['attributes']['popular_threat_classification']:
                popular_threat_category = result['data']['attributes']['popular_threat_classification']['popular_threat_category'][0]['value']
                file.write(f"\nPopular Threat Category:  {popular_threat_category}\n")
        
        # Print Names with which this file has been submiited or seen in the wild
            if 'names' in result['data']['attributes']:
                file.write("\nNames:\n")
                file.write("------\n")
                for name in result['data']['attributes']['names']:
                    file.write(f"  - {name}\n")
        
        # History of the sample
            file.write("\n\nHistory:\n")
            file.write("--------\n")
            if "creation_date" in result["data"]["attributes"]:
                creation_time = result["data"]["attributes"]["creation_date"]
                file.write(f"  - Creation Date          :{datetime.datetime.fromtimestamp(creation_time)}\n")
            first_submission_date = result['data']['attributes']['first_submission_date']
            file.write(f"  - First Submission Date  :{datetime.datetime.fromtimestamp(first_submission_date)}\n")
            last_submission_date = result['data']['attributes']['last_submission_date']
            file.write(f"  - Last Submission Date   :{datetime.datetime.fromtimestamp(last_submission_date)}\n")
            last_modification_date = result['data']['attributes']['last_modification_date']
            file.write(f"  - Last Modification Date :{datetime.datetime.fromtimestamp(last_modification_date)}\n")
            last_analysis_date = result['data']['attributes']['last_analysis_date']
            file.write(f"  - Last Analysis Date     :{datetime.datetime.fromtimestamp(last_analysis_date)}\n\n")
       
        # Info about the sample
            file.write("\nInfo:\n")
            file.write("----\n")
            meaningful_name = result['data']['attributes'].get('meaningful_name', 'None')
            file.write(f"  - Verdict: {meaningful_name}\n")
            file.write(f"  - File Size: {result['data']['attributes']['size']} bytes \n")
            file.write(f"  - File Type: {result['data']['attributes']['type_description']}\n")
            file.write(f"  - Magic: {result['data']['attributes']['magic']}\n")            
            file.write(f"  - Entry Point: {result['data']['attributes']['pe_info']['entry_point']}\n")
            file.write(f"  - Times Submitted: {result['data']['attributes']['times_submitted']}\n")
            file.write(f"  - File Type Tag: {result['data']['attributes']['type_tag']}\n")
            file.write(f"  - File Reputation Score: {result['data']['attributes']['reputation']}\n")
            file.write(f"  - Community Score: {result['data']['attributes']['last_analysis_stats']['malicious']}\n")
        
        # Getting threat names
            popular_threat_names = [entry['value'] for entry in result['data']['attributes']['popular_threat_classification']['popular_threat_name']]
            popular_threatnames = ", ".join(popular_threat_names)
            file.write(f"  - Popular Threat Category: {popular_threatnames}\n")
        
        # Getting threat tags  
            tags = [tag for tag in result['data']['attributes']['tags']]
            tag = ", ".join(tags)
            file.write(f"  - Tags: {tag}\n")
        
        # Getting verdicts
            if 'sandbox_verdicts' in result['data']['attributes']:
                first_sandbox_verdict = next(iter(result['data']['attributes']['sandbox_verdicts'].values()))  
                if 'malware_classification' in first_sandbox_verdict:
                    malware_class = ', '.join(first_sandbox_verdict['malware_classification'])
                    file.write(f"  - Malware Classification: {malware_class}\n")
                else:
                    file.write("Malware Classification: None\n")
            else:
                file.write("Malware Classification: None\n")

        # Retrieve further information
            if 'sections' in result['data']['attributes']['pe_info']:
                file.write("\n\nSections (Entropy):")
                file.write("\n-------------------\n") 
                for section in result['data']['attributes']['pe_info']['sections']:
                    file.write(f"  - {section['name']} ({section['entropy']})")
                    if section['entropy'] >= 7.5:
                        file.write("  ~ obfuscated section ~")
                    file.write("\n")
                    
            if 'packers' in result['data']['attributes']:
                file.write("\n\nPackers:")
                file.write("\n-------\n") 
                for key, value in result['data']['attributes']['packers'].items():
                    file.write(f"  - {key}: {value}\n")

            if 'signature_info' in result['data']['attributes']:
                file.write("\n\nSignature Info:")
                file.write("\n---------------\n") 
                for key, value in result['data']['attributes']['signature_info'].items():
                    file.write(f"  - {key}: {value}\n")

            if 'trid' in result['data']['attributes']:
                file.write(f"\n\nTrID (file type identification):")
                file.write("\n---------------------------------\n") 
                for item in result['data']['attributes']['trid']:
                    file.write(f"  - {item['file_type']}\n")
            
            if 'export' in result['data']['attributes']['pe_info']:
                file.write(f"\n\nDLL Exported Functions:")
                file.write("\n-----------------------\n") 
                for export in result['data']['attributes']['pe_info']['exports']:
                    file.write(f"  - {export}\n")

            if 'compiler_product_versions' in result['data']['attributes']['pe_info']:
                file.write("\n\nCompiler Products:")
                file.write("\n-----------------\n") 
                for product in result['data']['attributes']['pe_info']['compiler_product_versions']:
                    file.write(f"  - {product}\n")

        # Engines Detected
            file.write(f"\n\nEngines Detected: ({result['data']['attributes']['last_analysis_stats']['malicious']})\n")
            file.write("----------------------\n")
            not_detected_engines = []
            for engine, result_data in result['data']['attributes']['last_analysis_results'].items():
                if result_data['result'] is None:
                    not_detected_engines.append(engine)
                elif result_data['result']:
                    file.write(f"  - {engine}: {result_data['result']}\n")          
        
        # Engines UnDetected
            file.write(f"\n\nEngines Undetected: ({len(not_detected_engines)})\n")
            file.write("------------------------\n")
            for engine in not_detected_engines:
                file.write(f"  - {(engine)}\n")
        
    else:
        with open(output_file, "w") as file:
            file.write("\tVirusTotal check failed! OR No such file available in VT.")
