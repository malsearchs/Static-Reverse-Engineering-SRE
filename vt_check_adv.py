#!/usr/bin/python3
# coding: utf-8

import json
import os

def extract_vt_details(json_file_path, output_file):
    with open(json_file_path, "r") as file:
        data = json.load(file)
        file_behaviours = data["data"]
        
        with open(output_file, "a+") as output:
            output.write("\n\n\n\n\n\n\n\n\n\n") 
            output.write("+++++++++++++++++++++++++++++++++\n") 
            output.write("VirusTotal File Behavior Analysis\n")
            output.write("+++++++++++++++++++++++++++++++++\n")
            
        # Extracting File Behaviour ID            
            for behaviour in file_behaviours:
                attributes = behaviour.get("attributes", {})
                output.write(f"\n\nFile Behaviour ID: {behaviour['id']}\n")

        # Extracting Processes Trees              
                processes_tree = attributes.get("processes_tree", [])
                if processes_tree:
                    output.write("\n\nProcesses Tree:\n")
                    output.write("---------------\n") 
                    for process in processes_tree:
                        output.write(f"  - Process ID: {process['process_id']}, \nName: {process['name']}\n")

        # Extracting Processes Created              
                processes_created = attributes.get("processes_created", [])
                if processes_created:
                    output.write("\n\nProcesses Created:\n")
                    output.write("-------------------\n") 
                    for process in processes_created:
                        output.write(f"  - {process}\n")
             
        # Extracting Processes Terminated              
                processes_terminated = attributes.get("processes_terminated", [])
                if processes_terminated:
                    output.write("\n\nProcesses Terminated:\n")
                    output.write("-----------------------\n") 
                    for process in processes_terminated:
                        output.write(f"  - {process}\n")

        # Extracting Memory Pattern Domains               
                memory_pattern_domains = attributes.get("memory_pattern_domains", [])
                if memory_pattern_domains:
                    output.write("\n\nMemory Pattern Domains:\n")
                    output.write("-----------------------\n") 
                    for domain in memory_pattern_domains:
                        output.write(f"  - {domain}\n")

        # Extracting HTTP Conversations - URLs               
                http_conversations = attributes.get("http_conversations", [])
                if http_conversations:
                    output.write("\n\nHTTP Conversations - URLs:\n")
                    output.write("--------------------------\n") 
                    for conversation in http_conversations:
                        output.write(f"  - {conversation['url']}\n")

        # Extracting Memory Pattern URLs                
                memory_pattern_urls = attributes.get("memory_pattern_urls", [])
                if memory_pattern_urls:
                    output.write("\n\nMemory Pattern URLs:\n")
                    output.write("--------------------\n") 
                    for url in memory_pattern_urls:
                        output.write(f"  - {url}\n")

        # Extracting Mitre Attack Techniques                
                mitre_attack_techniques = attributes.get("mitre_attack_techniques", [])
                if mitre_attack_techniques:
                    output.write("\n\nMitre Attack Techniques:\n")
                    output.write("------------------------\n") 
                    for technique in mitre_attack_techniques:
                        output.write(f"  - ID: {technique['id']}, \nDescription: {technique['signature_description']}, \nSeverity: {technique.get('severity', 'N/A')}\n")

        # Extracting DNS Lookups                
                dns_lookups = attributes.get("dns_lookups", [])
                if dns_lookups:
                    output.write("\n\nDNS Lookups:\n")
                    output.write("-------------\n") 
                    for lookup in dns_lookups:
                        hostname = lookup.get("hostname")
                        resolved_ips = lookup.get("resolved_ips")
                        output.write(f"  - Hostname: {hostname}\n")
                        if resolved_ips:
                            for ip in resolved_ips:
                                output.write(f"    - Resolved IP: {ip}\n")

        # Extracting Modules Loaded
                modules_loaded = attributes.get("modules_loaded", [])
                if modules_loaded:
                    output.write("\n\nModules Loaded:\n")
                    output.write("---------------\n") 
                    for key in modules_loaded:
                        output.write(f"  - {key}\n")

        # Extracting Services Opened
                services_opened = attributes.get("services_opened", [])
                if services_opened:
                    output.write("\n\nServices Opened:\n")
                    output.write("---------------\n") 
                    for key in services_opened:
                        output.write(f"  - {key}\n")

        # Extracting Mutexes Opened
                mutexes_opened = attributes.get("mutexes_opened", [])
                if mutexes_opened:
                    output.write("\n\nMutexes Opened:\n")
                    output.write("---------------\n") 
                    for key in mutexes_opened:
                        output.write(f"  - {key}\n")

        # Extracting Files Opened
                files_opened = attributes.get("files_opened", [])
                if files_opened:
                    output.write("\n\nFiles Opened:\n")
                    output.write("--------------\n") 
                    for key in files_opened:
                        output.write(f"  - {key}\n")

        # Extracting Files Written
                files_written = attributes.get("files_opened", [])
                if files_written:
                    output.write("\n\nFiles Written:\n")
                    output.write("--------------\n") 
                    for key in files_written:
                        output.write(f"  - {key}\n")                   

        # Extracting Files Deleted
                files_deleted = attributes.get("files_deleted", [])
                if files_deleted:
                    output.write("\n\nFiles Deleted:\n")
                    output.write("--------------\n") 
                    for key in files_deleted:
                        output.write(f"  - {key}\n")

        # Extracting IP Traffics
                ip_traffic = attributes.get("ip_traffic", [])
                if ip_traffic:
                    output.write("\n\nIP Traffic:\n")
                    output.write("-------------\n") 
                    for ip_info in ip_traffic:
                        protocol = ip_info.get("transport_layer_protocol")
                        dest_ip = ip_info.get("destination_ip")
                        dest_port = ip_info.get("destination_port")
                        output.write(f"  - Protocol: {protocol}, \nDestination IP: {dest_ip}, \nDestination Port: {dest_port}\n")

        # Extracting Registry Opened                
                registry_keys_opened = attributes.get("registry_keys_opened", [])
                if registry_keys_opened:
                    output.write("\n\nRegistry Keys Opened:\n")
                    output.write("----------------------\n") 
                    for key in registry_keys_opened:
                        output.write(f"  - {key}\n")

        # Extracting Registry Keys Deleted
                registry_keys_deleted = attributes.get("registry_keys_deleted", [])
                if registry_keys_deleted:
                    output.write("\n\nRegistry Keys Deleted:\n")
                    output.write("----------------------\n") 
                    for key in registry_keys_deleted:
                        output.write(f"  - {key}\n")

# Delete the json file 
    filename = f"{json_file_path}"
    try:
        os.remove(filename)
    except FileNotFoundError:
        print(f"File {filename} not found.")
    except Exception as e:
        print(f"An error occurred while deleting {filename}: {e}")
