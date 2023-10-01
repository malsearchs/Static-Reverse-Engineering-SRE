#!/usr/bin/python3
# coding: utf-8

import platform
import subprocess

def extract_disassembly(file_path, output_file):
    os = platform.system()
    if os == "Linux":
        try:
            codedump_output = subprocess.check_output(["objdump", "--disassembler-color=off", "-M intel", "--debugging", "-h", "-r", "-s", "-t", "-D", file_path], universal_newlines=True)
        except FileNotFoundError:
            print("objdump command not found, get objdump installed.")
            return ""
        except subprocess.CalledProcessError:
            print("Error running objdump command.")
            return ""
    else:
        try:
            codedump_output = subprocess.check_output(["dumpbin", "/ALL", "/DISASM", file_path],universal_newlines=True)
        except FileNotFoundError:
            print("dumpbin command not found, get Visual Studio installed!")
            return ""
        except subprocess.CalledProcessError:
            print("Error running dumpbin command.")
            return ""

    with open(output_file, "w") as file:
        file.write("+++++++++++++++++\n")    
        file.write("Disassembly Code\n")
        file.write("+++++++++++++++++\n")
        file.write(codedump_output)