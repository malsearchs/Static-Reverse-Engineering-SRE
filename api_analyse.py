#!/usr/bin/python3
# coding: utf-8

import pefile
import re

def analyze_apis(file_path, output_file):
    api_analyse = []
    pe = pefile.PE(file_path)
    with open(file_path, "r", errors="ignore") as file:
        content = file.read()

# Get the Imported APIs
    imported_apis = []
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name:
                    imported_apis.append(imp.name.decode())

# Get Exported APIs
    exported_apis = []
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name:
                exported_apis.append(exp.name.decode())

# Networking APIs - raw sockets and winAPI sockets
    network_apis = []
    networking_apis = [
        (r"socket()", "raw_sockets"),
        (r"bind()", "raw_sockets"),
        (r"listen()", "raw_sockets"),
        (r"accept()", "raw_sockets"),
        (r"connect()", "raw_sockets"),
        (r"read()", "raw_sockets"),
        (r"recv()", "raw_sockets"),
        (r"write()", "raw_sockets"),
        (r"shutdown()", "raw_sockets"),
        (r"WSAStratup()", "winAPI_sockets"),
        (r"bind()", "winAPI_sockets"),
        (r"listen()", "winAPI_sockets"),
        (r"accept()", "winAPI_sockets"),
        (r"connect()", "winAPI_sockets"),
        (r"recv()", "winAPI_sockets"),
        (r"send()", "winAPI_sockets"),
        (r"WSACleanup()", "winAPI_sockets"),
    ]
    for api, socks in networking_apis:
        if re.findall(api, content, re.IGNORECASE):
            network_apis.append((api, socks))

# Look for Persistence APIs - Registry, Files, Services and Processes
    persistence_api_reg = re.findall(r"RegOpenKeyExA|RegGetValueA|RegCreateKeyExA|RegCloseKey|RegQueryValueExA|RegSetValueExA|RegSetValue|RegOpenKey|RegCreateKeyA|MachineGUID", content, re.IGNORECASE)
    api_analyse.extend(persistence_api_reg)

    persistence_api_file = re.findall(r"CopyFile|MoveFile|CreateFile|WriteFile|ReadFile|DeleteFile|GetFileSize|SHGetKnownFolderPath|MapViewOfFile|SfcTerminateWatcherThread|SetFileAttributes|SetFilePointer|SetFileTime|GetFileAttributes|FindFirstFile|FindNextFile", content, re.IGNORECASE)
    api_analyse.extend(persistence_api_file)

    persistence_api_srv = re.findall(r"OpenSCManager|WaitForSingleObject|CreateService|OpenSCManagerA|StartServiceCtrlDispatcher|StartService|CloseServiceHandle|CreateProcess", content, re.IGNORECASE)
    api_analyse.extend(persistence_api_srv)

    persistence_api_proc = re.findall(r"LeaveCriticalSection|CreateProcess|CreateProcessWithTokenW|CreateProcessWithLogonW|EnterCriticalSection|GetThreadContext|CloseHandle|CreateRemoteThread|OpenProcess|Thread32First|Thread32Next|CreateProcessAsUser|GetStartupInfo", content, re.IGNORECASE)
    api_analyse.extend(persistence_api_proc)

# Look for Crytographic APIs
    crypto_api = re.findall(r"BCryptCreateHash|BCryptDecrypt|BCryptDeriveKey|BCryptDeriveKeyCapi|BCryptDestroyHash|BCryptDestroyKey|BCryptEncrypt|BCryptExportKey|BCryptFreeBuffer|BCryptGenerateKeyPair|BCryptGenRandom|BCryptImportKey|BCryptSignHash|BCryptHash|BCryptGenerateSymmetricKey|BCryptHashData|RemoveDirectory|PathAppend|PathCombine|MessageBox|CreateWindow|RemoveDirectory|PathAppend|PathCombine|MessageBox|CreateWindow|NCryptEncrypt|NCryptDecrypt|NCryptEnumKeys|NCryptSignHash|NCryptVerifySignature|NCryptSecretAgreement|NCryptDeriveKey|WinCrypt|CryptAcquireContext|CryptGenKey|CryptDeriveKey|CryptUnprotectData|CryptAcquireContext|CryptReleaseContext|Crypt32CryptGenKey|CryptDecrypt|CryptEncrypt|CryptDestroyKey|CryptImportKey|CryptAcquireContextA|CryptCreateHash|CryptDeriveKey|CryptDestroyHash|CryptDestroyKey|CryptEnumProviderTypes|CryptGenRandom|CryptGetKeyParam|CryptGetUserKey|CryptHashData|CryptImportKey|CryptSignHash|CryptVerifySignature|Crypto|CryptUnprotectData|CryptImportKey|CryptExportKey|CryptGenKey|CryptGetRandom|CryptImportKey|CryptDestroyKey", content, re.IGNORECASE)
    api_analyse.extend(crypto_api)

# Look for Anti-Analysis / Virtual Machine (VM)
    anti_analyse = re.findall(r"IsDebuggerPresent|GetSystemInfo|GlobalMemoryStatusEx|GetVersionExA|CreateToolhelp32Snapshot|CreateFileW/A|GetVersion|DebugBreak|DebugBreakProcess|SetUnhandledExceptionFilter", content, re.IGNORECASE)
    api_analyse.extend(anti_analyse)

# Look for Stealthy APIs
    stealthy_api = re.findall(r"VirtualAlloc|Sleep|VirtualProtect|VirtualAllocEx|ReadProcessMemory|WriteProcessMemory|NtWriteVirtualMemory|RegisterHotKey|CreateRemoteThread|NtUnmapViewOfSection|QueueUserAPC|CreateMutexA|CreateMutexW|CreateProcessInternal|GetModuleHandle|FreeLibrary|MsWinZonesCacheCounterMutex", content, re.IGNORECASE)
    api_analyse.extend(stealthy_api)

# Look for Droppers and Downloaders APIs
    downloader_api = re.findall(r"URLDownloadToFile|SizeofResource|HttpOpenRequest|HttpSendRequest|InternetOpenUrl|URLDownloadToFileA|InternetReadFile|CreateDirectoryA|CreateDirectoryW|URLDownloadToFileW|SignalObjectAndWait|MsgWaitForMultipleObjectsEx|WaitForMultipleObjectsEx|WaitForSingleObjectEx", content, re.IGNORECASE)
    api_analyse.extend(downloader_api)

# Evade Detection by Anti Malwares
    evade_av = re.findall(r"ReleaseMutex|Mutex|CreateMutex|OpenMutex|MultiByteToWideChar|InitCommonControlsEx|SleepEx|NtDelayExecution|InitCommonControls|MsWinZonesCacheCounterMutexA|DeactivateActCtx|ActivateActCtx|ReleaseActCtx|CreateActCtx", content, re.IGNORECASE)

    with open(output_file, "w", errors="ignore") as file:
        file.write("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n")
        file.write("Extracted the Imported and Exported API calls and functions\n")
        file.write("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n")
        output_written = False

    # Write Imported APIs section
        if imported_apis:
            file.write(f"\nImported APIs - ({len(imported_apis)}):\n")
            file.write("---------------------\n")
            for api in imported_apis:
                file.write(f"{api}\n")
            output_written = True

    # Write Exported APIs section
        if exported_apis:
            file.write(f"\n\nExported APIs - ({len(exported_apis)}):\n")
            file.write("-----------------------\n")
            for api in exported_apis:
                file.write(f"{api}\n")
            output_written = True

    # Write Networking APIs section
        if network_apis:
            file.write(f"\n\nNetworking APIs - ({len(network_apis)}):\n")
            file.write("----------------------\n")
            for api, socks in network_apis:
                file.write(f"{api} ==> {socks}\n")
            output_written = True

    # Write Persistence APIs for Registries
        if persistence_api_reg:
            file.write(f"\n\nPersistence APIs for Registries - ({len(persistence_api_reg)}):\n")
            file.write("-------------------------------------\n")
            for persistant in persistence_api_reg:
                file.write(f"{persistant}\n")
            output_written = True
    # Write Persistence APIs for Files
        if persistence_api_file:
            file.write(f"\n\nPersistence APIs for Files - ({len(persistence_api_file)}):\n")
            file.write("----------------------------------\n")
            for persistant in persistence_api_file:
                file.write(f"{persistant}\n")
            output_written = True
    # Write Persistence APIs for Registries, Files, and Services section
        if persistence_api_srv:
            file.write(f"\n\nPersistence APIs for Services - ({len(persistence_api_srv)}):\n")
            file.write("----------------------------------\n")
            for persistant in persistence_api_srv:
                file.write(f"{persistant}\n")
            output_written = True

        if persistence_api_proc:
            file.write(f"\n\nPersistence APIs for Processes - ({len(persistence_api_proc)}):\n")
            file.write("---------------------------------------\n")
            for persistant in persistence_api_proc:
                file.write(f"{persistant}\n")
            output_written = True

    # Write Cryptographic APIs section
        if crypto_api:
            file.write(f"\n\nCryptographic APIs - ({len(crypto_api)}):\n")
            file.write("-------------------------\n")
            for crypto in crypto_api:
                file.write(f"{crypto}\n")
            output_written = True

    # Write Anti-Analysis / Virtual Machine (VM) APIs section
        if anti_analyse:
            file.write(f"\n\nAnti-Analysis / Virtual Machine (VM) - ({len(anti_analyse)}):\n")
            file.write("-------------------------------------------\n")
            for anti in anti_analyse:
                file.write(f"{anti}\n")
            output_written = True

    # Write Stealthy APIs section          
        if stealthy_api:
            file.write(f"\n\nStealthy APIs - ({len(stealthy_api)}):\n")
            file.write("--------------------\n")
            for stealthy in stealthy_api:
                file.write(f"{stealthy}\n")
            output_written = True
        
    # Write Downloader and Dropper APIs         
        if downloader_api:
            file.write(f"\n\nDownloader and Dropper APIs - ({len(downloader_api)}):\n")
            file.write("----------------------------------\n")
            for downloader in downloader_api:
                file.write(f"{downloader}\n")
            output_written = True
        
    # Write Evade Detections by Anit Malwares
        if evade_av:
            file.write(f"\n\nEvading Anti-Malwares - ({len(evade_av)}):\n")
            file.write("----------------------------\n")
            for evade in evade_av:
                file.write(f"{evade}\n")
            output_written = True

        if not output_written:
            file.write("\tNo Potential APIs in the binary. Proceed with Dynamic Reverse Engineering.\n")
            