#!/usr/bin/python3
# coding: utf-8

import pefile
import os
import yara
import lief
import math

def get_compiler_name(machine_code):
    compiler_mapping = {
        0x014C: "x86 (32-bit)-Windows [IMAGE_FILE_MACHINE_I386]",
        0x0200: "IA64 (Itanium)-Windows [IMAGE_FILE_MACHINE_IA64]",
        0x8664: "x64 (64-bit)-Windows [IMAGE_FILE_MACHINE_AMD64]",
        0x0003: "x86 (32-bit)-Linux",
        0x003E: "x86 (64-bit)-Linux",
        0x0028: "ARM-Linux",
        0x00B7: "AArch64-Linux",
        0x00EF: "PowerPC-Linux",
        0x0018: "MIPS-Linux"
    }
    return compiler_mapping.get(machine_code, "Unknown [IMAGE_FILE_MACHINE_UNKNOWN]")

# Calculate the entropy
    # Calculate entropy for each section header
def calculate_entropy(data):
    entropy = 0
    if data:
        byte_data = bytes(data)
        for x in range(256):
            p_x = float(byte_data.count(x))/len(byte_data)
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)
    return entropy

# Calculate entropy values
def categorize_entropy(entropy_value):
    if entropy_value >= 7.0:
        return 'High Entropy'
    elif entropy_value >= 3.0:
        return 'Medium Entropy'
    else:
        return 'Low Entropy'

# Get the details of the packers
# Thanks for Yara rules: https://github.com/Yara-Rules/rules 
def detect_packers(file_name, output_file):
    try:
        peid = yara.compile('config/peid.yar')
        packer = yara.compile('config/packer.yar')
        crypto = yara.compile('config/crypto.yar')
    except FileNotFoundError:
        print("The YARA files dont exist.")
    except IOError:
        print("An error occurred while reading the file. Check if they are the right files.")
        return []

# Check if the binary is singed
    filename = os.path.basename(file_name)
    pe = pefile.PE(file_name, fast_load=True)
    certificate_table = None 
    if hasattr(pe, 'DIRECTORY_ENTRY_SECURITY'):
        directory_entry = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']]
        certificate_table = pe.parse_certificates(directory_entry.VirtualAddress, directory_entry.Size)

# Dump all PE attributes
    dump_allinfo = pe.dump_info()
    binary = lief.parse(file_name)       
    machine_code = pe.FILE_HEADER.Machine
    compiler_details = f"Machine Type: {get_compiler_name(machine_code)}"

    with open(output_file, "w") as file:
        file.write("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n")
        file.write("Extracted the Compiler, Packer Details, Exported symbols & PE Dump\n")
        file.write("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n")
    # Compiler Detection Check
        file.write("\nCompiler Machine Type Details:\n")
        file.write("-----------------------------\n")
        file.write(compiler_details)

    # Check if the binary file is Signed or Not
        if certificate_table:
            file.write(f"\nThe binary '{filename}' is SIGNED.\n")
            for certificate in certificate_table:
                file.write("Certificate Information:")
                file.write(f"\tIssuer: {certificate.Issuer}")
                file.write(f"\tSubject: {certificate.Subject}")
                file.write(f"\tSerial Number: {certificate.SerialNumber}")
                file.write(f"\tThumbprint: {certificate.Thumbprint}")
                file.write(f"\tSignature Algorithm: {certificate.SignatureAlgorithm}")
                file.write(f"\tValid From: {certificate.NotBefore}")
                file.write(f"\tValid To: {certificate.NotAfter}")
        else:
            file.write(f"\n\n\nThe binary '{filename}' is NOT SIGNED.\n\n")

    # Packer Detection Check        
        file.write("\nPackers / Compilers Detected:\n")
        file.write("-----------------------------\n")
        peid_check = peid.match(file_name)
        if peid_check:
            for check in peid_check:
                file.write(f"{check}\n")
        packer_check = packer.match(file_name)
        if packer_check:
            for check in packer_check:
                file.write(f"{check}\n")

    # Crypto Detection Check
        rule_check = crypto.match(file_name)
        if rule_check:
            file.write("\n\nCrypto Details Detected:\n")
            file.write("------------------------\n")
            for check in rule_check:
                file.write(f"{check}\n")

# Section details with Virtual Address, Virtual Size, Offset, Raw Size and Calculating Entropy
# Calculate entropy to identify if the code is obfuscated /encrypted and compressed
# In cryptography, the most commonly used type of entropy is Shannon entropy, which was created by Claude Shannon, the father of information theory.
        file.write("\n\nSection Headers Details:\n")
        file.write("------------------------\n")
        threshold = 7.1
        file.write("{:<12} {:<10} {:<11} {:<11} {:<13} {:<22} {:<20} {:<20}\n".format(
            "Name", "RVA", "V_Size", "Offset", "Raw_Size", "Entropy", "Category", "Code_Obfuscation"))
        file.write("~" * 125 + "\n")
        for section in binary.sections:
            entropy = calculate_entropy(section.content)
            entropy_category = categorize_entropy(entropy)
            obfuscation_status = "* Obfuscated *" if entropy > threshold else "Not Obfuscated"
            file.write("{:<12} {:<10} {:<11} {:<11} {:<13} {:<22} {:<20} {:<20}\n".format(
                section.name, section.virtual_address, section.virtual_size,
                section.offset, section.size, entropy, entropy_category, obfuscation_status))

# Calculate entropy for the entire binary file
        filename = os.path.basename(file_name)
        binary_content = b"".join(section.content for section in binary.sections)
        binary_entropy = calculate_entropy(binary_content)
        binary_entropy_category = categorize_entropy(binary_entropy)
        binary_obfuscation_status = "Obfuscated" if binary_entropy > threshold else "Code Not Obfuscated"
        file.write(f"\nEntropy for entire binary file '{filename}'"": {}\n".format(binary_entropy))
        file.write("Entropy Category: {}\n".format(binary_entropy_category))
        file.write("Obfuscation Status: {}\n\n".format(binary_obfuscation_status))

# Dump all the attributes
        file.write("\n\nDumping all the information as full textual material\n")
        file.write("-----------------------------------------------------\n\n")
        file.write(dump_allinfo)
