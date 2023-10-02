#!/usr/bin/python3
# coding: utf-8
__version__  = "v1.0"  
__author__  = "malsearchs"
__email__  = "malsearchs [at] gmail [dot] com"
__url__  = "https://github.com/malsearchs/Static-Reverse-Engineering-SRE"
show_license = """\
Copyright (C) 2023 @malsearchs"""

import os, sys
import hashlib
import argparse
import time
import magic
from datetime import timedelta 

#colors courtesy: https://gist.github.com/vratiu/9780109

# Get the start time
start_time = time.time()

# Create the argument parser and define the required input parameter
class CustomFormatter(argparse.RawDescriptionHelpFormatter):
    def _format_text(self, text):
        return text + '\n\n'
# Check for incorrect options iseeulol!
def invalid_options(option):
    return f"Error: invalid option '{option}'\nTry 'SRE.py -h' for more information."
# Create the ArgumentParser object with the custom formatter
parser = argparse.ArgumentParser(prog='SRE.py', usage='%(prog)s [options] [filename]', description=' >>> Static Reverse Engineering SRE] <<< \n  Dissecting malware for static analysis', formatter_class=CustomFormatter)
if '-vv' in sys.argv or '-f' in sys.argv:
    parser.add_argument('filename', nargs='?', help="~state file path [to scan single file] or state folder path [to scan multiple files]\n")
else:
    parser.add_argument('filename', nargs='?', help="~state file path [to scan single file] or state folder path [to scan multiple files]\n")
parser.add_argument('-V', '--verbose', action='store_true', help='enable verbose terminal output')
parser.add_argument("-f",  "--file", action="store_true", help='check the file type only (before analyse)')
parser.add_argument('-v',  '--version', action="version", help="show version info", version=f"\n SRE {__version__}\n2023 Release" )
parser.add_argument('-i',  '--info', action="store_true", help=f"show author, email and url info")
parser.add_argument('-l',  '--license', action="store_true", help="show license info")
args = parser.parse_args()
parser.error = invalid_options

# Parameter check
if len(sys.argv) == 1:
    parser.print_help()
    sys.exit()

# Requried argument for verbose mode
if args.verbose:
    if not args.filename:
        print("\nError: the following arguments are required: filename")
        sys.exit(1)

# Print author info
if args.info:
    print(f"\nAuthor: {__author__}, Copyright (C) 2023")
    print(f"Email:    {__email__}")
    print(f"Website:  {__url__}\n\n")
    sys.exit()

# Print license info
if args.license:
    print(f"\n === Creative Commons Zero [CCO] v1.0 Universal License ===")
    print(f"\n{show_license}\n")
    sys.exit()

# Check if the provided input is a file or folder
if args.filename:
    if os.path.isfile(args.filename):
        files_to_analyze = [args.filename]
    elif os.path.isdir(args.filename):
        files_to_analyze = [os.path.join(args.filename, file) for file in os.listdir(args.filename)]
    else:
        print("\n\tError: Invalid Path. Give a valid file / folder path. Try '--help' to know more!")
        exit(1)
# Print file type and MIME
if args.file:
    if not args.filename:
        print("\nError: the following arguments are required: filename")
        sys.exit(1)
    else:
        for filename in args.filename:
            file_type = magic.from_file(args.filename)
            file_mime = magic.from_file(args.filename, mime = True)
            file_type_parts = file_type.split(",")
            try:
                if "PE32" in file_type  or "PE32+" in file_type or "DLL" in file_type:
                    print(f"\nIdentifying filetype _ ")  
                    for part in file_type_parts:
                        if "PE32" in part or "Intel" in part:
                            print(f"   File Type >>  {part.strip()}")
                    print(f"   MIME Type >>  {file_mime}")
                    print(f"   Supported File Type! Proceed to SRE.\n")
                    sys.exit(1)
                else:
                    print(f"\n|Identifying filetype _")
                    print(f"   File Type >>  {file_type}")
                    print(f"   MIME Type >> {file_mime}")
                    print(f"   Unsupported File Type! ")
                    sys.exit(1)
            except Exception as e:
                print("\n\tError: Invalid Path. Give a valid file / folder path. Try '--help' to know more!")
            sys.exit(1)  

# Create a directory to store the analysis results
output_dir = f"analysis_result_{os.path.splitext(os.path.basename(args.filename))[0]}"
os.makedirs(output_dir, exist_ok=True)

# Iterate over the files and perform analysis
for file_path in files_to_analyze:
    file_name = os.path.splitext(os.path.basename(file_path))[0]

if args.verbose:
    try:
        file_type = magic.from_file(file_path)
        print(f"\nIdentifying Filetype...", end=" ", flush=True)
        if "PE32" in file_type  or "PE32+" in file_type or "DLL" in file_type:
            print("Done!")
            print(f"\nAnalysing {file_name} _")
            from integrity_analyse import calculate_file_hashes
            from metadata_analyse import analyze_metadata
            from strings_analyse import analyze_strings
            from api_analyse import analyze_apis
            from packer_detections import detect_packers
            from ioc_extracts import extract_iocs
            from malicious_behavior_analyse import analyze_malicious_behavior
            from disasm_extracts import extract_disassembly
            from vt_checks import check_virustotal
            from vt_check_json import check_vt_advanced
            from vt_check_adv import extract_vt_details
        # Perform file integrity analysis
            try:
                print("   Extracting Hashes...", end=" ", flush=True)
                integrity_output = os.path.join(output_dir, f"{file_name}_integrity_hashes.txt")
                calculate_file_hashes(file_path, integrity_output)
                print("Done!")
            except Exception as e:
                print(f"An error occurred: {e}")

        # Perform metadata analysis
            try:
                print("   Extracting Metadata...", end=" ", flush=True)
                metadata_output = os.path.join(output_dir, f"{file_name}_metadata.txt")
                analyze_metadata(file_path, metadata_output)
                print("Done!")
            except Exception as e:
                print(f"An error occurred: {e}")
            
        # Perform string analysis
            try:
                print("   Extracting Strings...", end=" ", flush=True)
                string_output = os.path.join(output_dir, f"{file_name}_strings.txt")
                analyze_strings(file_path, string_output)
                print("Done!")
            except Exception as e:
                print(f"An error occurred: {e}")

        # Perform API analysis
            try:
                print("   Extracting APIs...", end=" ", flush=True)
                api_output = os.path.join(output_dir, f"{file_name}_apis.txt")
                analyze_apis(file_path, api_output)
                print("Done!")
            except Exception as e:
                print(f"An error occurred: {e}")

        # Perform packer detection
            try:
                print("   Extracting Packer Data...", end=" ", flush=True)
                packer_output = os.path.join(output_dir, f"{file_name}_packer_detection.txt")
                detect_packers(file_path, packer_output)
                print("Done!")
            except Exception as e:
                print(f"An error occurred: {e}")

        # Perform IOC extraction
            try:
                print("   Extracting IOCs...", end=" ", flush=True)
                ioc_output = os.path.join(output_dir, f"{file_name}_iocs.txt")
                extract_iocs(file_path, ioc_output)
                print("Done!")
            except Exception as e:
                print(f"An error occurred: {e}")

        # Perform malicious behavior analysis
            try:
                print("   Extracting Malicious Behaviours...", end=" ", flush=True)
                malicious_behavior_output = os.path.join(output_dir, f"{file_name}_malicious_behavior.txt")
                analyze_malicious_behavior(file_path, malicious_behavior_output)
                print("Done!")
            except Exception as e:
                print(f"An error occurred: {e}")

        # Perform Disassembly Code Extraction
            try:
                print("   Extracting Disassembly...", end=" ", flush=True)
                disasm_output = os.path.join(output_dir, f"{file_name}_disassembly_code.txt")
                extract_disassembly(file_path, disasm_output)
                print("Done!")
            except Exception as e:
                print(f"An error occurred: {e}")

        # Perform VirusTotal Check
            try:
                print("   Checking with VirusTotal...", end=" ", flush=True)
                vt_output = os.path.join(output_dir, f"{file_name}_virustotal_check.txt")
                check_virustotal(hashlib.sha256(open(file_path, "rb").read()).hexdigest(), vt_output)
                print("Done!")
            except Exception as e:
                print(f"An error occurred: {e}")

        # Import VT advanced JSON data (behaviours)
            try:
                vt_output = os.path.join(output_dir, f"{file_name}_virustotal_adv.json")
                check_vt_advanced(hashlib.sha256(open(file_path, "rb").read()).hexdigest(), vt_output)
            except Exception as e:
                print(f"An error occurred: {e}")

        # Extract JSON into readable TXT format
            try:
                vt_txt_output = os.path.join(output_dir, f"{file_name}_virustotal_check.txt")
                extract_vt_details(vt_output, vt_txt_output)
            except Exception as e:
                print(f"An error occurred: {e}")
        else:
            print(f"  Unsupported!\n\n  mOnly PE32/Executable & DLL file formates Supported.\n\n")
            sys.exit()
    except Exception as e:
        print(f"An error occurred: {e}")
        sys.exit()
else:
    try:
        file_type = magic.from_file(file_path)
        if "PE32" in file_type  or "PE32+" in file_type or "DLL" in file_type:
            print(f"\nAnalysing {file_name} _")
            from integrity_analyse import calculate_file_hashes
            from metadata_analyse import analyze_metadata
            from strings_analyse import analyze_strings
            from api_analyse import analyze_apis
            from packer_detections import detect_packers
            from ioc_extracts import extract_iocs
            from malicious_behavior_analyse import analyze_malicious_behavior
            from disasm_extracts import extract_disassembly
            from vt_checks import check_virustotal
            from vt_check_json import check_vt_advanced
            from vt_check_adv import extract_vt_details
        # Perform file integrity analysis
            try:
                integrity_output = os.path.join(output_dir, f"{file_name}_integrity_hashes.txt")
                calculate_file_hashes(file_path, integrity_output)
            except Exception as e:
                print(f"An error occurred: {e}")

        # Perform metadata analysis
            try:
                metadata_output = os.path.join(output_dir, f"{file_name}_metadata.txt")
                analyze_metadata(file_path, metadata_output)
            except Exception as e:
                print(f"An error occurred: {e}")
        
        # Perform string analysis
            try:
                string_output = os.path.join(output_dir, f"{file_name}_strings.txt")
                analyze_strings(file_path, string_output)
            except Exception as e:
                print(f"An error occurred: {e}")

        # Perform API analysis
            try:
                api_output = os.path.join(output_dir, f"{file_name}_apis.txt")
                analyze_apis(file_path, api_output)
            except Exception as e:
                print(f"An error occurred: {e}")

        # Perform packer detection
            try:
                packer_output = os.path.join(output_dir, f"{file_name}_packer_detection.txt")
                detect_packers(file_path, packer_output)
            except Exception as e:
                print(f"An error occurred: {e}")

        # Perform IOC extraction
            try:
                ioc_output = os.path.join(output_dir, f"{file_name}_iocs.txt")
                extract_iocs(file_path, ioc_output)
            except Exception as e:
                print(f"An error occurred: {e}")

        # Perform malicious behavior analysis
            try:
                malicious_behavior_output = os.path.join(output_dir, f"{file_name}_malicious_behavior.txt")
                analyze_malicious_behavior(file_path, malicious_behavior_output)
            except Exception as e:
                print(f"An error occurred: {e}")

        # Perform Disassembly Code Extraction
            try:
                disasm_output = os.path.join(output_dir, f"{file_name}_disassembly_code.txt")
                extract_disassembly(file_path, disasm_output)
            except Exception as e:
                print(f"An error occurred: {e}")

        # Perform VirusTotal Check
            try:
                vt_output = os.path.join(output_dir, f"{file_name}_virustotal_check.txt")
                check_virustotal(hashlib.sha256(open(file_path, "rb").read()).hexdigest(), vt_output)
            except Exception as e:
                print(f"An error occurred: {e}")

        # Import VT advanced JSON data (behaviours)
            try:
                vt_output = os.path.join(output_dir, f"{file_name}_virustotal_adv.json")
                check_vt_advanced(hashlib.sha256(open(file_path, "rb").read()).hexdigest(), vt_output)
            except Exception as e:
                print(f"An error occurred: {e}")

        # Extract JSON into text format
            try:
                vt_txt_output = os.path.join(output_dir, f"{file_name}_virustotal_check.txt")
                extract_vt_details(vt_output, vt_txt_output)
            except Exception as e:
                print(f"An error occurred: {e}")
        else:
            print(f"\nIdentifying Filetype...", end=" ", flush=True)
            print(f"  Unsupported!\n\n Only PE32/Executable & DLL file formates Supported.\n\n")
            sys.exit()
    except Exception as e:
        print(f"An error occurred: {e}")
        sys.exit()

for i in range(1000000):
    pass
end_time = time.time()
# Calculate the total execution time
total_time_count = end_time - start_time
total_time = str(timedelta(seconds=total_time_count)).split('.')[0]
# Print the total execution time in a readable format
print(f"\n   >> Extracted in [HH:MM:SS]: {total_time} ")
print(f"\nAnalysis completed & the outcome placed in 'analysis_result_{os.path.splitext(os.path.basename(args.filename))[0]}' folder.\n")
print(f"\t\t>>> Happy Static Reverse Engineering <<<\n")
