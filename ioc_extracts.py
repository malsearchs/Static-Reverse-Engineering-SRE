#!/usr/bin/python3
# coding: utf-8

import re

def check_ioc(data):
    iocs = []
    ascii_strings = re.findall(rb"(?i)[\x20-\x7E]{3,}", data)
    iocs.extend([string.decode() for string in ascii_strings])
    unicode_strings = re.findall(rb"(?i)(?:[\x20-\x7E]\x00){3,}|(?:[\x20-\x7E]\x00\x00){3,}", data)
    iocs.extend([string.decode() for string in unicode_strings])  
    return iocs

def search_iocs(strings, keywords):
    found = []
    for keyword in keywords:
        for string in strings:
            if re.search(re.escape(keyword), string, re.IGNORECASE):
                found.append(string)
    return found

def extract_iocs(file_path, output_file):
    with open(file_path, "rb") as file:
        binary_data = file.read()
    extracted_strings = check_ioc(binary_data) 

# Capture Windows Commands
    commands = r"@echo |echo |del /|move /|rmdir |start |shutdown |regsvr32|schtasks|runas|xcopy |reg |telnet|curl |icacls |ping -|chcp |cmd\.exe|attrib |wmic |psexec|wbemtest|powershell|-Command|certutil |taskkill |bitsadmin |netstat |net view|tasklist |regedit |netcat |net start|net stop|regsvr32 |exec |multiprocessing Process|WScript.Shell.Run|Net LocalGroupAddMembers|Net UserAdd|Net UserDel|Net UserEnum|Net UserGetGroups|Net UserGetLocalGroups|Net UserGetLocalGroups|Net UserGetMembers|Net UserMod|Net UserSetGroups|Net UserSetInfo|Net UserSetPassword|Net UserVerify"
    cmd = f'.*({commands}).*'     
    win_cmds = []                 
    for string in extracted_strings: 
        command = re.search(cmd, string, re.IGNORECASE)
        if command:
            win_cmds.append(command.group(0))    

# Capture Windows Folders/Paths
    paths = re.findall(r"IntelliForms|Storage2|Opera Stable|Drivers|YandexBrowser|\\Mozilla\s*Firefox|\\Profiles|All Users|AppData|ProgramData|\\Intel|SecurityCenter2|CIMV2", ' '.join(extracted_strings))
    windows_paths = list(set(search_iocs(extracted_strings, paths)))

# Extract file paths
    file_paths = re.findall(r"(?i)(?:[a-z]:\\|\\\\[a-z0-9_.$●-]+\\[a-z0-9_.$●-]+\\)(?:[a-z0-9_.$●-]+\\)*[a-z0-9_.$●-]+(?:\.[a-z0-9]+)?", ' '.join(extracted_strings))

# Capture Windows Shares & Folders
    win_folder_paths = re.findall(r"\\\\%s\\IPC\$|%d\.\d+\.\d+\.\d+|C:\\%s\\", ' '.join(extracted_strings))

# Capture Domain Names, URLs
    url = re.findall(r"https?:|//www|\.com|\.net|\.org|\.int|\.info|\.biz|\.pro|\.name|\.mobi|\.xxx", ' '.join(extracted_strings))
    urls = search_iocs(extracted_strings, url)

# Capture Registry Hives
    win_reghives = re.findall(r"HKEY_CLASSES_ROOT|HKEY_CURRENT_USER|HKEY_LOCAL_MACHINE|HKEY_USERS|HKEY_CURRENT_CONFIG", ' '.join(extracted_strings))
    registry_hives = search_iocs(extracted_strings, win_reghives)

# Capture Registry Paths
    win_registrys = r"Windows Defender|CurrentVersion|nuR|RunOnce|Wow6432Node|Classes\\|ControlSet001|Internet Settings|Browser Helper Objects|SharedAccess|FirewallPolicy|Evtx|\.DEFAULT|WindowsUpdate|RunServicesOnce|TaskScheduler|Userinit|LanmanServer|RunServices|Exclusions"
    reg = f'.*({win_registrys}).*'      
    win_reg = []                      
    for string in extracted_strings:  
        command = re.search(reg, string)
        if command:
            win_reg.append(command.group(0))

# Capture Executable files Created, Used or Dropped by
    exe_file = re.findall(r'\b\w+\.exe\b', ' '.join(extracted_strings))
    exe_files = list(set(search_iocs(extracted_strings, exe_file)))

# Capture DLL files Created, Used or Dropped by
    dll_files = re.findall(r'\b\w+\.dll\b', ' '.join(extracted_strings))

# Capture Configuration data
    config_data = re.findall(r"Copyright|LANMAN|workgroups|NTLM|NT LM|username|password|api_key|token | UID |SELECT |files have been encrypted|rights reserved| install |keychain|Bitcoin|Ransomware|Payment", ' '.join(extracted_strings),  re.IGNORECASE)
    configdata = list(set(search_iocs(extracted_strings, config_data)))

# Capture IP Addresses
    ip_address = re.findall(r"(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(?:\.(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3}", ' '.join(extracted_strings))
    ip_addresses = list(set(ip_address))

# Capture Protocols Uasge
    protocol_data = re.findall(r"TCP|SMB|FTP|SMTP|TCP/IP|SSH|SCP|WinSCP|SSL|HTTPS?|RDP|ARP|POP|IMAP|RTP|TOR|IRC|DNS|WebSocket|NTP|ICMP", ' '.join(extracted_strings))
    protocols = list(set(search_iocs(extracted_strings, protocol_data)))

# Capture Files Created, Used or Dropped by
    file_extensions = re.findall(r"\S+\.(?:txt|png|jpg|jpeg|gif|bat|bin|log|crypt|zip|hta|js|docx|lnk|drv|bat|ps|jar|mrc|msi|vbs|ini|inf)(?=\s|$)", ' '.join(extracted_strings), re.IGNORECASE)
    file_extension = list(set(search_iocs(extracted_strings, file_extensions)))
    
# Extract email addresses 
    emails = re.findall(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", ' '.join(extracted_strings))

# Extract Crypto Wallet addresses (Bitcoin and Ethereum, including both legacy and SegWit (Bech32) addresses)
    crypto_wallets = re.findall(r"\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1(?:[A-Za-z0-9]{39}|[A-Za-z0-9]{59}))\b", ' '.join(extracted_strings))

# Extract Known CVE Exploits
    known_CVE = re.findall(r"CVE-\d{4}-\d{4,7}", ' '.join(extracted_strings))

# Capture Version Numbers
    version_number = re.findall(r"\d{1,5}(?:\.\d{1,5}){2}", ' '.join(extracted_strings))
    version_numbers = list(set(search_iocs(extracted_strings, version_number)))

    with open(output_file, "w", errors="ignore") as file:
        file.write("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n")
        file.write("Extracted IOCs - IPs, URLs, Domains, emails, file paths and Crypto Wallets\n")
        file.write("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n")
        output_written = False

    # Check win commands
        if win_cmds:
            file.write("\n\nWindows Commands:\n")            
            file.write("-----------------\n") 
            for cmds in win_cmds:      
                file.write(f"{cmds}\n")
            output_written = True

    # Check win paths
        if windows_paths:
            file.write("\n\nWindows Folders:\n")
            file.write("----------------\n")
            for paths in windows_paths:
                file.write(f"{paths}\n")
            output_written = True

    # Check file paths
        if file_paths:
            file.write("\n\nWindows Drive Paths:\n")
            file.write("--------------------\n")
            for path in file_paths:
                file.write(f"{path}\n")
            output_written = True

    # Check domain names and urls
        if urls:
            file.write("\n\nDomain Names, URLs:\n")
            file.write("-------------------\n")
            for url in urls:
                file.write(f"{url}\n")
            output_written = True

    # Check win folder paths
        if win_folder_paths:
            file.write("\n\nWindows Shares & Folders:\n")
            file.write("-------------------------\n")
            for folder in win_folder_paths:
                file.write(f"{folder}\n")
            output_written = True

    # Check files created used or dropped by
        if file_extension:
            file.write("\n\nFiles Created, Used or Dropped by:\n")
            file.write("----------------------------------\n")
            for files in file_extension:
                file.write(f"{files}\n")
            output_written = True

    # Check win registry entries
        if win_reg:
            file.write("\n\nRegistry Entries:\n")
            file.write("-----------------\n")             
            for registry in win_reg:
                file.write(f"{registry}\n")
            output_written = True

    # Check reg hives
        if registry_hives:
            file.write("\n\nWindows Registry Hives:\n") 
            file.write("-----------------------\n")            
            for hives in registry_hives:
                file.write(f"{hives}\n")
            output_written = True

    # Check exe files created, used or dropped by
        if exe_files:
            file.write("\n\nExecutable Files Created, Used or Dropped by:\n")
            file.write("---------------------------------------------\n")
            for exe_file in exe_files:
                file.write(f"{exe_file}\n")
            output_written = True

    # Check dll files created, used or dropped by
        if dll_files:
            file.write("\n\nDLL Files Created, Used or Dropped by:\n")
            file.write("--------------------------------------\n") 
            for dll_file in dll_files:
                file.write(f"{dll_file}\n")
            output_written = True

    # Check IP addresses 
        if ip_addresses:
            file.write("\n\nIP Addresses:\n")
            file.write("-------------\n") 
            for ips in ip_addresses:
                octets = ips.split('.')
                if len(octets) != 4 or (octets[0] == '0') or (octets[1] == '0') or (octets[2] == '0' and octets[3] == '0'):
                    file.write(f"{ips} \t~~~possibly version info~~~\n")
                else:
                    file.write(f"{ips} \n")
            output_written = True

    # Check protocols used
        if protocols:
            file.write("\n\nProtocols Usage:\n")
            file.write("-----------------\n")
            for protocol in protocols:
                file.write(f"{protocol}\n")
            output_written = True

    # Check CVEs
        if known_CVE:
            file.write("\n\nKnown CVEs:\n")
            file.write("-----------\n")
            for cves in known_CVE:
                file.write(f"{cves}\n")
            output_written = True

    # Check config data
        if configdata:
            file.write("\n\nConfiguration Data:\n")
            file.write("-------------------\n") 
            for data in configdata:
                file.write(f"{data}\n")
            output_written = True

    # Check email addressed used
        if emails:
            file.write("\n\nEmail Addresses:\n")
            file.write("----------------\n") 
            for email in emails:
                file.write(f"{email}\n")
            output_written = True

    # Check crypto wallet addresses
        if crypto_wallets:
            file.write("\n\nCrypto Wallet Addresses:\n")
            file.write("------------------------\n") 
            for wallets in crypto_wallets:
                file.write(f"{wallets}\n")
            output_written = True

    # Check version details
        if version_numbers:
            file.write("\n\nVersion Details:\n")
            file.write("----------------\n") 
            for version in version_numbers:
                file.write(f"{version}\n")
            file.write("\n")
            output_written = True

        if not output_written:
            file.write("\tNo IOCs' extracted, file corrupted?  Proceed with Dynamic Reverse Engineering.\n") 
