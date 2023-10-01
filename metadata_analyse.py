#!/usr/bin/python3
# coding: utf-8

import os, time
import pefile
import magic
import lief

def analyze_metadata(file_path, output_file):
    metadata = {}
    exported_symbols = []
    imported_symbols = []
    metadata["File Size (in MB)"] = os.path.getsize(file_path)/(10**6) 
    pe = pefile.PE(file_path)
    metadata["Creation Timestamp"] = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(pe.FILE_HEADER.TimeDateStamp))

# Check for Compiler-Specific Metadata
    if hasattr(pe, "VS_FIXEDFILEINFO"):
        fixed_info = pe.VS_FIXEDFILEINFO[0]
        product_version_ms = fixed_info.ProductVersionMS
        product_version_ls = fixed_info.ProductVersionLS
        metadata["Product Version"] = f"{product_version_ms >> 16}.{product_version_ms & 0xFFFF}.{product_version_ls >> 16}.{product_version_ls & 0xFFFF}"
        metadata["File Version"] = f"{fixed_info.FileVersionMS >> 16}.{fixed_info.FileVersionMS & 0xFFFF}.{fixed_info.FileVersionLS >> 16}.{fixed_info.FileVersionLS & 0xFFFF}"
    section_names = ([section.Name.decode().rstrip('\x00') for section in pe.sections])
    metadata["Number of Sections"] = pe.FILE_HEADER.NumberOfSections, section_names               
    file_type = magic.from_file(file_path)
    file_mime = magic.from_file(file_path, mime = True)
    pe = pefile.PE(file_path)
    binary = lief.parse(file_path)
    debugs = binary.debug

# Check for Exported Symbols
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            exported_symbols.append((hex(pe.OPTIONAL_HEADER.ImageBase + exp.address),exp.name.decode() if exp.name else "",exp.ordinal,))

# Check for Imported Symbols
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name:
                   imported_symbols.append((entry.dll.decode(), hex(imp.address), imp.name.decode('utf-8'), imp.ordinal))

# Listing the Data Directories 
    def extract_data_directories(file_path):
        try:
            pe = pefile.PE(file_path)
        except pefile.PEFormatError as e:
            print("Error: Unable to parse the PE file.")
            return []

    # Extract Manifest file
    def extract_manifest(pe):
        manifest_content = ""
        try:
            for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if entry.id == pefile.RESOURCE_TYPE['RT_MANIFEST']:
                    offset = entry.directory.entries[0].directory.entries[0].data.struct.OffsetToData
                    size = entry.directory.entries[0].directory.entries[0].data.struct.Size
                    data = pe.get_memory_mapped_image()[offset : offset + size]
                    manifest_content = data.decode('utf-8', errors='ignore')
            return manifest_content
        except Exception as e:
            file.write(f"An error occurred: {e}")
            return None

    with open(output_file, "w") as file:
        file.write("++++++++++++++++++++++++++++++++++++\n")
        file.write("Extracted the binary file's metadata\n")
        file.write("++++++++++++++++++++++++++++++++++++\n")
        file.write(f"\nFile Type: {file_type}\n")
        file.write(f"\nFile MIME: {file_mime}\n")
        for key, value in metadata.items():
            file.write(f"\n{key}: {value}\n")      

# Dump DOS Headers & Optional Headers attributes
        file.write("\n\nFile's DOS Headers & Optional Headers:\n")
        file.write("--------------------------------------\n")
        file.write("===Dos Header===\n")
        file.write(str(binary.dos_header))
        file.write("\n\n===Header===\n")
        file.write(str(binary.header))
        file.write("\n\n===Optional Header===\n")
        file.write(str(binary.optional_header))
        file.write("\n\n===Debug===\n")
        if debugs:
            for entry in debugs:
                file.write(str(entry))
        else:
            file.write("No debug info found!\n")

# Check for Exported Symbols
        if exported_symbols:
            file.write("\n\nExported Symbols\n")
            file.write("-----------------\n") 
            file.write("RVA\t\tName  (Ordinal)\n") 
            file.write("~" * 40 + "\n")         
            for symbol in exported_symbols:
                file.write(f"{symbol[0]}\t{symbol[1]}  ({symbol[2]})\n")

# Check for Imported Symbols
        try:    
            if imported_symbols:
                file.write("\n\nImported Symbols\n")
                file.write("-----------------\n")     
                file.write("DLL\t RVA\t\tSymbol\n")
                file.write("~" * 45)
                name = imp.name.decode() 
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    file.write(f"\n{entry.dll.decode()} - ({len(entry.imports)})\n")
                    for imp in entry.imports:
                        if imp.name:
                            name = imp.name.decode()
                        file.write(f"\t {hex(imp.address)}\t{name}\n")
        except pefile.PEFormatError as e:
            file.write(f"Error while parsing the PE file. {(str(e))}\n")
            return []

# Listing the section headers and associated directories
        section_headers = extract_data_directories(file_path)
        file.write("\n\n\nListing the Data Directories:\n")
        file.write("----------------------------\n")
        file.write("{:<40} {:<13} {:<7}\n".format("Data Directories", "RVA", "Size"))
        file.write("~" * 60 + "\n")
        for data_directory in pe.OPTIONAL_HEADER.DATA_DIRECTORY:
            name = data_directory.name 
            file.write("{:<40} {:<13} {:<7}\n".format(name,hex(data_directory.VirtualAddress),data_directory.Size))
        manifest_content = extract_manifest(pe)
        if manifest_content:
            file.write("\n\nManifest Content:\n")
            file.write("-----------------\n")
            file.write(manifest_content)
