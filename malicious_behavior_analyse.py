#!/usr/bin/python3
# coding: utf-8

import re
import pefile

def analyze_malicious_behavior(file_path, output_file):
    malicious_behavior = []
    with open(file_path, "r", errors="ignore") as file:
        content = file.read()
        pe = pefile.PE(file_path)

# Look for code injection & code obfuscations techniques
        code_injection = re.findall(r"BASE64|Decode|BASE128|Passthru|SuspendThread|WriteProcessMemory", content, re.IGNORECASE)
        code_injections = list(set(code_injection))
        malicious_behavior.extend(code_injections)

# Ananlyse Command Execution techniques
        command_execution_patterns = re.findall(r"ShellExecute|UseShellExecute|Execute|PowerShell|ShellExecuteEx|WinExec|ShellExecuteEx|ShellExecute|PeekNamedPipe|CreatePipe|ConnectNamedPipe|WScript|WshShell|LocalGroupAddMembers|UserAdd|UserDel|UserEnum|UserGetGroups|UserGetLocalGroups|UserGetLocalGroups|UserGetMembers|UserMod|UserSetGroups|UserSetInfo|UserSetPassword|UserVerify", content, re.IGNORECASE)
        malicious_behavior.extend(command_execution_patterns)

# Ananlyse Windows Commands - CMD 
        windows_cmds = re.findall(r"rmdir|icacls \. /grant Everyone:F|cmd\.exe /c|attrib \+h|runas|everyone|wmic|psexec|ping|del|chcp|@echo off|schtasks|start|shutdown|move|@echo|certutil|taskkill|bitsadmin|netstat|tasklist|regedit|netcat|net start|net stop|regsvr32|shell|exec|multiprocessing Process|WScript.Shell.Run|Net LocalGroupAddMembers|Net UserAdd|Net UserDel|Net UserEnum|Net UserGetGroups|Net UserGetLocalGroups|Net UserGetLocalGroups|Net UserGetMembers|Net UserMod|Net UserSetGroups|Net UserSetInfo|Net UserSetPassword|Net UserVerify", content, re.MULTILINE)
        windows_cmd_commands = list(set(windows_cmds))
        malicious_behavior.extend(windows_cmd_commands)

# Extract Windows Folders Paths
        windows_folders = re.findall(r"\WIntel\W|\WProgramData\W|\WProgram Files\W|\WProgram Files\(86\)\W|\WSystem32\W|\WUsers\W|\WWindows\W|\Wtemp\W|\WSysWOW64\W|\WWindowsPowerShell\W|\Wwinevt\W", content, re.IGNORECASE)
        malicious_behavior.extend(windows_folders)

# Ananlyse Windows Commands - PowerShell
        windows_ps_commands = re.findall(r"PowerShell|PS\.exe|Invoke-WmiMethod|Invoke-Shellcode|Get-NetNeighbor|Get-NetworkRange|Invoke-ReflectivePEInjection|Get-WMIObject|Invoke-WebRequest|New-PSSession|Start-Process|IEX|Copy-Item|Remove-Item|Start-BitsTransfer|Start-ProcessCopy-Item|Move-Item|Remove-Item|Get-ItemProperty|Set-ItemProperty|Test-NetConnection|Resolve-DnsName|Get-Service|Start-Service|Stop-Service|Invoke-ScriptBlock|Get-Credential|Test-NetConnection|Resolve-DnsName", content)  
        malicious_behavior.extend(windows_ps_commands)

# Ananlyse Windows Registry Hives
        registry_hives = re.findall(r"HKEY_CLASSES_ROOT|HKEY_CURRENT_USER|HKEY_LOCAL_MACHINE|HKEY_USERS|HKEY_CURRENT_CONFIG", content, re.IGNORECASE | re.MULTILINE)
        malicious_behavior.extend(registry_hives)

# File Operations
        file_operation = re.findall(r"open|read|write|delete|rename|fclose|fopen|fputc|fputs|fread|fwrite|CopyFileA|CopyFileW|CopyFileEx|MoveFileA|MoveFileW|MoveFileEx|CreateFileA|CreateFileW|CreateFileEx|ReadFile|WriteFile|DeleteFile|SHGetKnownFolderPath|MapViewOfFile|SfcTerminateWatcherThread|SetFileAttributes|SetFilePointer|SetFileTime|GetFileSizeEx|GetFileSize|GetFileAttributes|NtQueryInformationByName|NtQueryInformationFile|FindFirstFile|FindNextFile", content, re.IGNORECASE)
        file_operations = list(set(file_operation))
        malicious_behavior.extend(file_operations)

# Analyse Network Communications
    # Look for HTTP libraries
        network_communication = re.findall(r"HttpSendRequestEx|HttpEndRequestA|WinHttpOpen|WinHttpConnect|WinHttpSendRequest|InternetWriteFile|URLDownloadToFile|HttpOpenRequestA|htonl|htons|ntohl|ntohs", content, re.IGNORECASE)
        malicious_behavior.extend(network_communication)
        
    # Look for Socket functions
        socket_function = re.findall(r"socket|bind|accept|connect|send|recv|closesocket|ioctlsocket|listen", content, re.IGNORECASE)
        socket_functions = list(set(socket_function))
        malicious_behavior.extend(socket_functions)

    # Look for WebSocket libraries
        websocket_libraries = re.findall(r"websocket|websockets|WebSocketCreateClientHandle|WebSocketCreateServerHandle|WebSocketReceive|WebSocketSend|WebSocketAbortHandle|WebSocketGetAction|WebSocketDeleteHandle|WebSocketCreateClientHandle|WebSocketCreateServerHandle", content, re.IGNORECASE)
        malicious_behavior.extend(websocket_libraries)

    # Look for DNS functions
        dns_functions = re.findall(r"gethostbyname|gethostbyaddr|getpeername|getsockname", content, re.IGNORECASE)
        malicious_behavior.extend(dns_functions)

    # Look for FTP/SSH functions
        ftp_functions = re.findall(r"FTP|FtpPutFile|FtpOpenFile|FileZilla|SFTP|TFTP|SCP|SSHd|SSH|WinSCP", content)
        malicious_behavior.extend(ftp_functions)

    # Look for VPN libraries
        vpn_libraries = re.findall(r"OpenVPN|SoftEther|VPN", content)
        malicious_behavior.extend(vpn_libraries)

    # Look for cryptographic functions
        crypto_libraries = re.findall(r"OpenSSL|Crypto|Crypt32|eSTREAM|Curve|XOR|AES|RSA|X509Chain|TLS|SHA|SHA256|SHA512|SHA384|hash|ECC|ECDSA|ECDH|Cipher|OpenPGP|HMACSHA256|MD5|X509", content)
        malicious_behavior.extend(crypto_libraries)

# Look for Data Exfiltration
        data_exfiltration = re.findall(r"base64\.|hexlify\.|binascii\.", content, re.IGNORECASE)
        malicious_behavior.extend(data_exfiltration)

# Look for Anti-analysis Technique
        anti_analysis = re.findall(r"IsDebuggerPresent|CheckRemoteDebuggerPresent|OutputDebugString|NtQueryInformationProcess|GetTickCount|GetSystemTime|SetUnhandledExceptionFilter", content, re.IGNORECASE)
        malicious_behavior.extend(anti_analysis)

# Look for DLL Injections and Code Hooking Techniques
        code_hooking = re.findall(r"GetModuleHandle|LoadLibrary|CreateRemoteThread|LdrLoadDll|SetWindowsHookEx|GetProcAddress|DetourTransactionBegin|DetourUpdateThread|DetourAttach|LD_PRELOAD", content, re.IGNORECASE)
        malicious_behavior.extend(code_hooking)

# Look for Process Injection Techniques
        process_injection = re.findall(r"VirtualAllocEx|CreateThread|WriteProcessMemory|ResumeThread|CreateMutexA|OpenMutex|TerminateThread|TerminateProcess|GetCurrentProcess|SetThreadContext|GetCommandLineA|GetCommandLineW", content, re.IGNORECASE)
        malicious_behavior.extend(process_injection)

# Look for Suspicious Registry Operations
        registry_operations = re.findall(r"RegOpenKeyEx|RegOpenKey|RegGetValue|RegGetValueEx|RegQueryValueExW|RegCreateKeyEx|RegCreateKey|RegQueryValue|RegCloseKey|RegQueryValueEx|RegSetValueEx|RegSetValue|RtlCreateRegistryKey|RtlWriteRegistryValue|WritePrivateProfileString|MachineGUID", content)
        malicious_behavior.extend(registry_operations)

# Look for Persistence Mechanisms
        persistence = re.findall(r"CreateTask|ModifyStartupFolder|ModifySystemServices|SetCurrentDirectory|CreateDirectory|GetTempPath|GetWindowsDirectory", content, re.IGNORECASE)
        malicious_behavior.extend(persistence)

# Look for Privilege Escalation Attempts
        privilege_escalation = re.findall(r"setuid|sudo|IsNTAdmin|ModifySystemConfig|AdjustTokenPrivileges|DeviceIoControl|NtSetInformationProcess|OpenProcessToken", content, re.IGNORECASE)
        malicious_behavior.extend(privilege_escalation)

# Look for Suspicious Network Traffic Patterns
        net_traffic = re.findall(r"Recv|ConnectNamedPipe|Bind|inet_addr|Send|WSAStartup|inet_ntoa|IcmpSendEcho", content, re.IGNORECASE)
        network_traffic = list(set(net_traffic))
        malicious_behavior.extend(network_traffic)

# Look for Memory Manipulation Techniques
        memory_manipulation = re.findall(r"VirtualAlloc|VirtualProtect|WriteProcessMemory|ReadProcessMemory|EnableExecuteProtectionSupport|Toolhelp32ReadProcessMemory|CopyMemory|Memmove|Memset|memcmp|malloc|calloc|realloc|LocalAlloc|GlobalAlloc|LocalFree|HeapAlloc|HeapFree|InterlockedIncrement|InterlockedDecrement|InterlockedExchange", content, re.IGNORECASE)
        malicious_behavior.extend(memory_manipulation)

# Look for Key Logging
        key_logging = re.findall(r"GetAsyncKeyState|EnableWindow|SetWindowsHookEx|MapVirtualKey|AttachThreadInput|GetKeyState|GetWindowDC", content, re.IGNORECASE)
        malicious_behavior.extend(key_logging)

# Look for Running window details, Websites from Browsers & Running processes
        running_window = re.findall(r"GetForegroundWindow|CreateToolhelp32Snapshot", content, re.IGNORECASE)
        malicious_behavior.extend(running_window)

# Look for Screenshot         
        screenshot = re.findall(r"GetDCEx|BitBlt|GetWindowDC|GetDC", content, re.IGNORECASE)
        malicious_behavior.extend(screenshot)

# Look for Access the Internet
        access_internet = re.findall(r"InternetOpen|InternetOpenA|InternetOpenUrl|InternetReadFile|InternetWriteFile|InternetConnectA|InternetCloseHandle", content, re.IGNORECASE)
        malicious_behavior.extend(access_internet)

# Look for Access the Executable Resources
        access_exe_reource = re.findall(r"FindResource|LoadResource|LockResource|SizeofResource|SetCurrentDirectoryA", content, re.IGNORECASE)
        malicious_behavior.extend(access_exe_reource)

# Execute a program or open a file from within another program
        exe_program = re.findall(r"ShellExecute|ShellExecuteEx|SHELLEXECUTEINFO|ShellExecuteExA|ShellExecuteExW|ShellExecuteHook|NetScheduleJobAdd", content, re.IGNORECASE)
        malicious_behavior.extend(exe_program)

# Look for System Enumerations
        system_enumeration = re.findall(r"EnumProcesses|GetOEMCP|GetCPInfoExA|GetNativeSystemInfo|EnumProcessModules|GetSecurityInfo|GetAdaptersInfo|NetShareEnum|FindFirstFile|FindResource|FindNextFile|FindWindow|GetCurrentProcess|GetStartupInfo|GetTempPath|Gethostname|GetWindowsDirectory|GetSystemDefaultLangId|GetVersionEx|Module32First|Module32Next|IsWoW64Process|Process32First|Process32Next|LsaEnumerateLogonSessions|GetLogicalDevices|SystemParametersInfo|SamIConnect|SamIGetPrivateData|SamQueryInformationUse|GetCPInfoEx|GetComputerName|GetSystemInfo|GetDriveTypeW|GetDriveTypeA|FindFirstVolumeW|FindNextVolumeW|GetVolumePathNamesForValueName", content, re.IGNORECASE)
        malicious_behavior.extend(system_enumeration)

# Look for Services & Processes Manipulation
        service_manipulation = re.findall(r"StartServiceCtrlDispatcher|LeaveCriticalSection|EnterCriticalSection|GetModuleFileName|WaitForSingleObject|OpenSCManagerA|Thread32First|Thread32Next|OpenProcess|QueueUserAPC|CreateProcess|CreateRemoteThread|CreateService|CloseServiceHandle|CloseHandle|CreateToolhelp32Snapshot|GetModuleFilename|GetThreadContext|StartServiceA|UnlockFile|LockFile|CreateProcessAsUser|CreateProcessWithLogonW|CreateProcessWithTokenW|SignalObjectAndWait|MsgWaitForMultipleObjectsEx|WaitForMultipleObjectsEx|NtQueryInformationToken|WaitForSingleObjectEx|OpenProcessToken|GetCommandLine", content, re.IGNORECASE)
        malicious_behavior.extend(service_manipulation)

# Clipboard Hijacking
        clipboard_hijacking = re.findall(r"OpenClipboard|GetClipboardData|EnumClipboardFormats|EmptyClipboard|CloseClipboard|SetClipboardData", content)
        malicious_behavior.extend(clipboard_hijacking)

# Detection Evade Techniques
        evade_detect = re.findall(r"InitCommonControlsEx|InitCommonControls|CreateMutex|OpenMutex|MultiByteToWideChar|NtDelayExecution|SetWaitableTimer|CreateTimerQueueTimer|CreateProcessInternal", content)
        malicious_behavior.extend(evade_detect)

# Look for Bootkit or Rootkit Injection Techniques
        boot_root_kits = re.findall(r"ZwOpenProcess|ZwWriteVirtualMemory|ZwAllocateVirtualMemory|ZwProtectVirtualMemory|ZwQuerySystemInformation|ZwSetSystemInformation|ZwCreateThreadEx|ZwCreateUserProcess|ZwQueueApcThread|ZwSetInformationThread|ZwLoadDriver|ZwEnumerateValueKey|ZwQueryDirectoryFile|ZwSetInformationFile|ZwOpenProcessToken|ZwQueryInformationProcess", content, re.IGNORECASE)
        malicious_behavior.extend(boot_root_kits)

# Look for Ransomware Crypto Techniques
        ransom_crypt = re.findall(r"RNGCryptoServiceProvider|GetFullPathName|BCryptCreateHash|BCryptDecrypt|BCryptDeriveKey|BCryptDeriveKeyCapi|BCryptDestroyHash|BCryptDestroyKey|BCryptEncrypt|BCryptExportKey|BCryptFreeBuffer|BCryptGenerateKeyPair|BCryptGenRandom|BCryptImportKey|BCryptSignHash|BCryptHash|BCryptGenerateSymmetricKey|BCryptHashData|RemoveDirectory|PathAppend|PathCombine|MessageBox|CreateWindow|RemoveDirectory|PathAppend|PathCombine|MessageBox|CreateWindow|NCryptEncrypt|NCryptDecrypt|NCryptEnumKeys|NCryptSignHash|NCryptVerifySignature|NCryptSecretAgreement|NCryptDeriveKey|WinCrypt|CryptAcquireContext|CryptGenKey|CryptDeriveKey|CryptUnprotectData|CryptAcquireContext|CryptReleaseContext|Crypt32CryptGenKey|CryptDecrypt|CryptEncrypt|CryptDestroyKey|CryptImportKey|CryptAcquireContextA|CryptCreateHash|CryptHashData|CryptDeriveKey|CryptDestroyHash|CryptDestroyKey|CryptEnumProviderTypes|CryptGenRandom|CryptGetKeyParam|CryptGetUserKey|CryptHashData|CryptImportKey|CryptSignHash|CryptVerifySignature|Crypto|CryptUnprotectData|CryptImportKey|CryptExportKey|CryptGenKey|CryptGetRandom|CryptImportKey|CryptDestroyKey|MsWinZonesCacheCounterMutexA", content, re.IGNORECASE)
        malicious_behavior.extend(ransom_crypt)

# Writing into output file
    with open(output_file, "w") as file:
        file.write("++++++++++++++++++++++++++++++++++++++++++++++++++++\n")
        file.write("Extracted potential malicious behaviors in the code\n")
        file.write("++++++++++++++++++++++++++++++++++++++++++++++++++++\n")
        output_written = False  
        def find_dll_for_api(api, pe):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name is not None and imp.name.decode(errors="ignore") == api:
                        return entry.dll.decode(errors="ignore")
            return None
    
    # Check code injections
        if code_injections:
            file.write("\nCode Injections and Obfuscations:\n")
            file.write("---------------------------------\n") 
            for behaviors in code_injections:
                dll = find_dll_for_api(behaviors, pe)
                if dll is not None:
                    file.write(f"{behaviors.ljust(22)}[from {dll}]\n")
                else:
                    file.write(f"{behaviors.ljust(22)}\n")
            output_written = True
    
    # Check cmd execution patterns
        if command_execution_patterns:
            file.write("\n\nCommand Executions:\n")
            file.write("--------------------\n") 
            for command_exec in command_execution_patterns:
                dll = find_dll_for_api(command_exec, pe)
                if dll is not None:
                    file.write(f"{command_exec.ljust(22)}[from {dll}]\n")
                else:
                    file.write(f"{command_exec.ljust(22)}\n")
            output_written = True
    
    # Check win cmd check
        if windows_cmd_commands:
            file.write("\n\nWindows Commands - CMD:\n")
            file.write("-----------------------\n") 
            for win_cmd in windows_cmd_commands:
                file.write(f"{win_cmd}\n")
            output_written = True  
    # Check powershell cmd
        if windows_ps_commands:
            file.write("\n\nWindows Commands - Powershell:\n")
            file.write("------------------------------\n") 
            for win_ps in windows_ps_commands:
                file.write(f"{win_ps}\n")
            output_written = True  

    # Check win folders
        if windows_folders:           
            file.write("\n\nWindows Folders:\n")
            file.write("----------------\n") 
            for win_folder in windows_folders:
                file.write(f"{win_folder}\n")
            output_written = True 

    # Check registry hives
        if registry_hives:           
            file.write("\n\nWindows Registry Hives:\n")
            file.write("------------------------\n") 
            for reg_hive in registry_hives:
                file.write(f"{reg_hive}\n")
            output_written = True 

    # Check file ops
        if file_operations:
            file.write("\n\nFile Operations:\n")
            file.write("----------------\n") 
            for behavior in file_operations:
                dll = find_dll_for_api(behavior, pe)
                if dll is not None:
                    file.write(f"{behavior.ljust(22)}[from {dll}]\n")
                else:
                    file.write(f"{behavior.ljust(22)}\n")
            output_written = True

    # Check network comms
        if network_communication:
            file.write("\n\nNetwork Communications:\n")
            file.write("------------------------\n") 
            for behavior in network_communication:
                dll = find_dll_for_api(behavior, pe)
                if dll is not None:
                    file.write(f"{behavior.ljust(18)}[from {dll}]\n")
                else:
                    file.write(f"{behavior.ljust(18)}\n")
            output_written = True

    # Check socket comms
        if socket_functions:
            file.write("\n\nSocket functions:\n")
            file.write("------------------\n") 
            for socket in socket_functions:
                dll = find_dll_for_api(socket, pe)
                if dll is not None:
                    file.write(f"{socket.ljust(18)}[from {dll}]\n")
                else:
                    file.write(f"{socket.ljust(18)}\n")
            output_written = True
        
        if websocket_libraries:
            file.write("\n\nWebSocket libraries:\n")
            file.write("---------------------\n") 
            for websocket in websocket_libraries:
                dll = find_dll_for_api(websocket, pe)
                if dll is not None:
                    file.write(f"{websocket.ljust(18)}[from {dll}]\n")
                else:
                    file.write(f"{websocket.ljust(18)}\n")
            output_written = True  

    # Check dns comms
        if dns_functions:
            file.write("\n\nDNS functions:\n")
            file.write("----------------\n") 
            for dns in dns_functions:
                dll = find_dll_for_api(dns, pe)
                if dll is not None:
                    file.write(f"{dns.ljust(18)}[from {dll}]\n")
                else:
                    file.write(f"{dns.ljust(18)}\n")
        output_written = True

    # Check ftp comms
        if ftp_functions:
            file.write("\n\nFTP/SSH functions:\n") 
            file.write("--------------------\n") 
            for ftp in ftp_functions:
                dll = find_dll_for_api(ftp, pe)
                if dll is not None:
                    file.write(f"{ftp.ljust(18)}[from {dll}]\n")
                else:
                    file.write(f"{ftp.ljust(18)}\n")
            output_written = True

    # Check vpn comms
        if vpn_libraries:
            file.write("\n\nVPN libraries:\n") 
            file.write("----------------\n") 
            for vpn in vpn_libraries:
                dll = find_dll_for_api(vpn, pe)
                if dll is not None:
                    file.write(f"{vpn.ljust(18)}[from {dll}]\n")
                else:
                    file.write(f"{vpn.ljust(18)}\n")
            output_written = True 

    # Check cryto libraries
        if crypto_libraries:
            file.write("\n\nCryptographic libraries:\n") 
            file.write("------------------------\n") 
            for crypto in crypto_libraries:
                dll = find_dll_for_api(crypto, pe)
                if dll is not None:
                    file.write(f"{crypto.ljust(18)}[from {dll}]\n")
                else:
                    file.write(f"{crypto.ljust(18)}\n")
            output_written = True

    # Check data exfils
        if data_exfiltration:
            file.write("\n\nData Exfiltration:\n")
            file.write("-------------------\n") 
            for behavior in data_exfiltration:
                dll = find_dll_for_api(behavior, pe)
                if dll is not None:
                    file.write(f"{behavior.ljust(18)}[from {dll}]\n")
                else:
                    file.write(f"{behavior.ljust(18)}\n")
            output_written = True  
    
    # Check anti-debug 
        if anti_analysis:
            file.write("\n\nAnti-analysis Techniques:\n")
            file.write("-------------------------\n") 
            for behavior in anti_analysis:
                dll = find_dll_for_api(behavior, pe)
                if dll is not None:
                    file.write(f"{behavior.ljust(18)}[from {dll}]\n")
                else:
                    file.write(f"{behavior.ljust(18)}\n")
            output_written = True

    # Check code hooking
        if code_hooking:
            file.write("\n\nDLL Injection & Code Hooking Techniques:\n")
            file.write("----------------------------------------\n") 
            for hooking in code_hooking:
                dll = find_dll_for_api(hooking, pe)
                if dll is not None:
                    file.write(f"{hooking.ljust(18)}[from {dll}]\n")
                else:
                    file.write(f"{hooking.ljust(18)}\n")
            output_written = True
    
    # Check process injections
        if process_injection:
            file.write("\n\nProcess Injection Techniques:\n")
            file.write("------------------------------\n") 
            for injection in process_injection:
                dll = find_dll_for_api(injection, pe)
                if dll is not None:
                    file.write(f"{injection.ljust(18)}[from {dll}]\n")
                else:
                    file.write(f"{injection.ljust(18)}\n")
            output_written = True
    
    # Check registry ops
        if registry_operations:
            file.write("\n\nSuspicious Registry Operations:\n")
            file.write("-------------------------------\n") 
            for registry in registry_operations:
                dll = find_dll_for_api(registry, pe)
                if dll is not None:
                    file.write(f"{registry.ljust(18)}[from {dll}]\n")
                else:
                    file.write(f"{registry.ljust(18)}\n")
            output_written = True
        
    # Check persistence mechanisms
        if persistence:
            file.write("\n\nPersistence Mechanisms:\n")
            file.write("-----------------------\n") 
            for persistant in persistence:
                dll = find_dll_for_api(persistant, pe)
                if dll is not None:
                    file.write(f"{persistant.ljust(18)}[from {dll}]\n")
                else:
                    file.write(f"{persistant.ljust(18)}\n")
            output_written = True

    # Check privilege escalations
        if privilege_escalation:
            file.write("\n\nPrivilege Escalation Attempts:\n")
            file.write("------------------------------\n") 
            for privilege in privilege_escalation:
                dll = find_dll_for_api(privilege, pe)
                if dll is not None:
                    file.write(f"{privilege.ljust(18)}[from {dll}]\n")
                else:
                    file.write(f"{privilege.ljust(18)}\n")
        output_written = True
    
    # Check suspicious network traffic
        if network_traffic:
            file.write("\n\nSuspicious Network Traffic Patterns:\n")
            file.write("------------------------------------\n") 
            for traffic in network_traffic:
                dll = find_dll_for_api(traffic, pe)
                if dll is not None:
                    file.write(f"{traffic.ljust(18)}[from {dll}]\n")
                else:
                    file.write(f"{traffic.ljust(18)}\n")
            output_written = True
    
    # Check memory manipulations 
        if memory_manipulation:
            file.write("\n\nMemory Manipulation Techniques:\n")
            file.write("-------------------------------\n") 
            for memory in memory_manipulation:
                dll = find_dll_for_api(memory, pe)
                if dll is not None:
                    file.write(f"{memory.ljust(18)}[from {dll}]\n")
                else:
                    file.write(f"{memory.ljust(18)}\n")
            output_written = True

    # Check key loggers
        if key_logging:
            file.write("\n\nKey Logging:\n")
            file.write("------------\n")
            for keylogs in key_logging:
                dll = find_dll_for_api(keylogs, pe)
                if dll is not None:
                    file.write(f"{keylogs.ljust(18)}[from {dll}]\n")
                else:
                    file.write(f"{keylogs.ljust(18)}\n")
            output_written = True

    # Check current running windows & browser actions
        if running_window:
            file.write("\n\nRunning window or Website from Browser Info:\n")
            file.write("--------------------------------------------\n") 
            for match in running_window:
                dll = find_dll_for_api(match, pe)
                if dll is not None:
                    file.write(f"{match.ljust(18)}[from {dll}]\n")
                else:
                    file.write(f"{match.ljust(18)}\n")
            output_written = True

    # Check screenshots capture
        if screenshot:
            file.write("\n\nScreenshot:\n")
            file.write("-----------\n") 
            for screen in screenshot:
                dll = find_dll_for_api(screen, pe)
                if dll is not None:
                    file.write(f"{screen.ljust(18)}[from {dll}]\n")
                else:
                    file.write(f"{screen.ljust(18)}\n")
            output_written = True
        
    # Check internet access
        if access_internet:
            file.write("\n\nAccess Internet:\n")
            file.write("----------------\n") 
            for iaccess in access_internet:
                dll = find_dll_for_api(iaccess, pe)
                if dll is not None:
                    file.write(f"{iaccess.ljust(18)}[from {dll}]\n")
                else:
                    file.write(f"{iaccess.ljust(18)}\n")
            output_written = True

    # Check executable resources
        if access_exe_reource: 
            file.write("\n\nAccess Executable Resources:\n")
            file.write("----------------------------\n")
            for eaccess in access_exe_reource:
                dll = find_dll_for_api(eaccess, pe)
                if dll is not None:
                    file.write(f"{eaccess.ljust(18)}[from {dll}]\n")
                else:
                    file.write(f"{eaccess.ljust(18)}\n")
            output_written = True

    # Check service and process manipulations
        if exe_program:
            file.write("\n\nFile Execution & Process Creation:\n")
            file.write("----------------------------------\n") 
            for exeprgm in exe_program:
                dll = find_dll_for_api(exeprgm, pe)
                if dll is not None:
                    file.write(f"{exeprgm.ljust(18)}[from {dll}]\n")
                else:
                    file.write(f"{exeprgm.ljust(18)}\n")
            output_written = True

    # Check system enumerations 
        if system_enumeration:
            file.write("\n\nSystem Enumerations:\n")
            file.write("----------------------------------\n") 
            for system in system_enumeration:
                dll = find_dll_for_api(system, pe)
                if dll is not None:
                    file.write(f"{system.ljust(18)}[from {dll}]\n")
                else:
                    file.write(f"{behavior.ljust(18)}\n")
            output_written = True

    # Check service manipulations
        if service_manipulation:
            file.write("\n\nServices & Processes Manipulation:\n")
            file.write("--------------------\n") 
            for service in service_manipulation:
                dll = find_dll_for_api(service, pe)
                if dll is not None:
                    file.write(f"{service.ljust(18)}[from {dll}]\n")
                else:
                    file.write(f"{service.ljust(18)}\n")
            output_written = True

    # Check hijacking clipboard
        if clipboard_hijacking:
            file.write("\n\nClipboard Hijacking:\n")
            file.write("--------------------\n") 
            for clipboard in clipboard_hijacking:
                dll = find_dll_for_api(clipboard, pe)
                if dll is not None:
                    file.write(f"{clipboard.ljust(18)}[from {dll}]\n")
                else:
                    file.write(f"{clipboard.ljust(18)}\n")
            output_written = True

    # Check evade detections
        if evade_detect:
            file.write("\n\nDetection Evade Techniques:\n")
            file.write("----------------------------------------\n") 
            for evade in evade_detect:
                dll = find_dll_for_api(evade, pe)
                if dll is not None:
                    file.write(f"{evade.ljust(18)}[from {dll}]\n")
                else:
                    file.write(f"{evade.ljust(18)}\n")
            output_written = True

    # Check bootkits & rootkits injection
        if boot_root_kits:
            file.write("\n\nBootkit or Rootkit Injection Techniques:\n")
            file.write("----------------------------------------\n") 
            for kits in boot_root_kits:
                dll = find_dll_for_api(kits, pe)
                if dll is not None:
                    file.write(f"{kits.ljust(18)}[from {dll}]\n")
                else:
                    file.write(f"{kits.ljust(18)}\n")
            output_written = True

    # Check ransomware crypto functions
        if ransom_crypt:
            file.write("\n\nRansomware Crypto Techniques:\n")
            file.write("-----------------------------\n") 
            for ransom in ransom_crypt:
                dll = find_dll_for_api(ransom, pe)
                if dll is not None:
                    file.write(f"{ransom.ljust(18)}[from {dll}]\n")
                else:
                    file.write(f"{ransom.ljust(18)}\n")
            output_written = True

        if not output_written:
            file.write("\tNo Potential Malicious Behavior in the code, Proceed with Dynamic Reverse Engineering.\n")
