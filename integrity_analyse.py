#!/usr/bin/python3
# coding: utf-8

import hashlib
import pefile, os

def calculate_hash(data, algorithm="sha256"):
    hash_func = hashlib.new(algorithm)
    hash_func.update(data)
    return hash_func.hexdigest()

def calculate_section_hashes(pe_file):
    section_hashes = {}
    try:
        pe = pefile.PE(data=pe_file)
        for section in pe.sections:
            section_data = pe_file[section.PointerToRawData: section.PointerToRawData + section.SizeOfRawData]
            section_name = section.Name.decode().rstrip('\x00')
            section_hashes[section_name] = {
                "MD5":      calculate_hash(section_data, "md5"),
                "SHA1":     calculate_hash(section_data, "sha1"),
                "SHA2-256": calculate_hash(section_data, "sha256"),
                "SHA2-512": calculate_hash(section_data, "sha512"), 
                "SHA3-256": calculate_hash(section_data, "sha3_256"), 
                "SHA3-512": calculate_hash(section_data, "sha3_512") 
            }
    except Exception as e:
        print(f"Error parsing PE file: {e}")
    return section_hashes

def calculate_file_hashes(file_path, output_file):
    try:
        with open(file_path, "rb") as file:
            content = file.read()

        hashes = {
            "MD5":      calculate_hash(content, "md5"),
            "SHA1":     calculate_hash(content, "sha1"),
            "SHA2-256": calculate_hash(content, "sha256"),
            "SHA2-512": calculate_hash(content, "sha512"),
            "SHA3-256": calculate_hash(content, "sha3_256"),
            "SHA3-512": calculate_hash(content, "sha3_512") 
        }

        with open(output_file, "w") as file:
            file.write("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n")
            file.write("Generated the MD5, SHA1, SHA2 and SHA3 hashes of the binary file\n")
            file.write("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n\n")
            filepath = os.path.splitext(os.path.basename(file_path))[0]
            file.write(f"{filepath} File's Hash Values:\n")
            file.write(f"{('-' * len(filepath))}--------------------\n")
            for algorithm, hash_value in hashes.items():
                file.write(f"  {algorithm}: {hash_value}\n")

        section_hashes = calculate_section_hashes(content)
        with open(output_file, "a") as file:
            file.write(f"\n\n\n  Hashes of each Section Header:")
            file.write("\n  ------------------------------\n")
            for section_name, hashes in section_hashes.items():
                file.write(f"    Section: {section_name}\n")
                file.write(f"    ~~~~~~~~~{'~' * (len(section_name))}\n")
                for hash_algorithm, section_hash_value in hashes.items():
                    file.write(f"      {hash_algorithm}: {section_hash_value}\n")
                file.write("\n")
    except Exception as e:
        print(f"Error processing file: {e}")
