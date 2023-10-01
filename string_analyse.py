#!/usr/bin/python3
# coding: utf-8

import re
import pefile

def analyze_strings(file_path, output_file):
    strings = []
    section_strings = {}
    with open(file_path, "rb") as file:
        binary_data = file.read()
    pe = pefile.PE(file_path)
    content = binary_data.decode(errors="ignore")

    # Extract ASCII strings
    ascii_strings = re.findall(rb"(?i)[\x20-\x7E]{3,}", binary_data)
    strings.extend([(None, string.decode()) for string in ascii_strings])

    # Extract Unicode strings
    unicode_strings = re.findall(rb"(?i)(?:[\x20-\x7E]\x00){3,}|(?:[\x20-\x7E]\x00\x00){3,}", binary_data)
    strings.extend([(None, string.decode()) for string in unicode_strings])

    # Extract hexadecimal strings
    hex_strings = re.findall(rb"([0-9A-Fa-f]{2}){4,}", binary_data)
    strings.extend([(None, string.decode()) for string in hex_strings])

    # Extract configuration data
    config_data = re.findall(r"([\w.-]+)=(.*)|\b(?:username |password |api_key |token |UID )\b", content, re.IGNORECASE)
    strings.extend([(None, f"{key}={value}") for key, value in config_data])

    # Extract URL patterns
    url_patterns = re.findall(r"(?i)(?:http|ftp)s?://(?:[^\s/]+)(?:[^\s]*)", content)
    strings.extend([(None, string) for string in url_patterns])

    # Collect the Imported DLLs
    def extract_imported_dlls(file_path):
        imported_dlls = []
        pe = pefile.PE(file_path)
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                imported_dlls.append(entry.dll.decode())
        return imported_dlls

    # Extract strings for each section
    for section in pe.sections:
        section_data = binary_data[section.PointerToRawData : section.PointerToRawData + section.SizeOfRawData]
        section_name = section.Name.decode().rstrip('\x00')
        section_strings[section_name] = extract_strings_from_section(section_data)

    # Writing the strings into the output file
    with open(output_file, "w") as file:
        file.write("++++++++++++++++++++++++++++++++++++++\n")
        file.write("Strings extracted from the binary file\n")
        file.write("++++++++++++++++++++++++++++++++++++++\n")   
        output_written = False 
        
    # Collect all the imported DLL files
        dlls = extract_imported_dlls(file_path)
        file.write(f"\n\nImported DLLs:({len(dlls)})\n")
        file.write("-----------------\n")
        for dll in dlls: 
            file.write(f"{dll}\n")
        output_written = True

        if hex_strings:
            file.write("\n\nHexadecimal Strings:\n")
            file.write("--------------------\n") 
            for string in hex_strings:
                file.write(string.decode() + " ")
            file.write("\n")
            output_written = True

        if url_patterns:
            file.write("\n\nURLs:\n")
            file.write("-----\n") 
            for string in url_patterns:
                file.write(f"{string}\n\n")
            output_written = True

        if config_data:
            file.write("\n\nConfiguration Data:\n")
            file.write("-------------------\n") 
            for string in config_data:
                file.write(f"{string}\n\n")
            output_written = True

    # Import All Section Headers
        section_names = [section.Name.decode().rstrip('\x00') for section in pe.sections]
        file.write(f"\nAvailable Section Headers:({len(section_names)})\n")
        file.write("----------------------------\n")
        for name in section_names:
            file.write(f"\t{name}\n")

        file.write("\n\nStrings extracted from the Section Headers:\n")
        file.write("-------------------------------------------\n")
        for section_name, section_strings_list in section_strings.items():
            file.write(f"\nStrings Extracted from:[{section_name}]\n")
            file.write(f"~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n")
            if section_strings_list:
                for string in section_strings_list:
                    file.write(f"[{section_name}]\t {string}\n")
            else:
                file.write("\tNo strings found.\n")
            output_written = True

        if not output_written:
            file.write("\tNo Strings extracted, file corrupted?  Proceed with Dynamic Reverse Engineering.\n")   
    pe.close()

def extract_strings_from_section(data):
    strings = []
    ascii_strings = re.findall(rb"(?i)[\x20-\x7E]{3,}", data)
    strings.extend([string.decode() for string in ascii_strings])
    unicode_strings = re.findall(rb"(?i)(?:[\x20-\x7E]\x00){3,}|(?:[\x20-\x7E]\x00\x00){3,}", data)
    strings.extend([string.decode() for string in unicode_strings])
    return strings
