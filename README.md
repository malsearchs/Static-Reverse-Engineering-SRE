# Static Reverse Engineering [SRE]
### SRE - Dissecting Malware For Static Analysis & The Complete Command-line Tool

SRE is designed to dissect the binary files (such as EXE, DLL file types) for Static Analysis, such as malware samples, to extract valuable data without executing the file. Its built with a comprehensive set of analysis techniques and generates text files containing the outcomes for further analysis or report creation, also very juicy data for Dynamic Analysis.

 #### <u>_ **Key Features:** _</u>
**Static Analysis:** The tool performs static analysis, which means it examines the binary file without executing or running it. This helps in understanding the characteristics and potential behavior of the file.

**Text File based Output:** The tool saves the analysis outcome as text file. This format is chosen to facilitate easy access, review, and further analysis of the collected information. It allows analysts to search, filter, and process the data conveniently.  Also very helpful to write custom 'Yara rules'.

**200+ Checkpoints:** The tool encompasses 90 different checkpoints categorized into nine distinct categories. These checkpoints cover a wide range of analysis techniques, aiming to provide a comprehensive data of the binary file.


### **Categories of Analysis:**
By performing a thorough analysis across the following nine categories which contains 200+ checkpoints (will increase occasionally), this provides a comprehensive understanding of the binary file's characteristics, behavior, and potential risks.

-   **Integrity Analyse**
-   **Metadata Analyse**
-   **Packer Detection**
-   **API Analyse**
-   **String Analyse**
-   **IoC Extraction**
-   **Malicious Behaviour Analyse**
-   **Disasmembly Dump**
-   **VirusTotal Check**     _<Note: this will not submit the samples to VT.>_

The tool works only on command line, that can be used to perform static reverse engineering on malicious Windows binary files (exe, dll), and it will dump all the outcome as text files under the analysis_result_<binaryfilename> directory generated by this tool. Since all the outcome as text files it would much easier for further analysis and/or create detailed report.

     _TIP:  if the binary file's name as 'malware.exe', recommended rename it as 'malware_exe' to create meaningful output directory and file names._

**Advantages:**
- The complete command-line tool with text files as output. <First of this kind I guess!>
- The outcome text files makes useful in further analyze the results and/or create a detailed report and to write custom Yara rules.  Also these dump very handy during Dynamic Analysis of this sample.
- It is a command line tool, which makes it easy to use and automate, also can be customized further for more specialized research.

**Limitations:**
-  Its all command-line based and no GUI treats!
-  Supports only EXE, DLL file formates (as of now)
-  It may not be a perfect tool, and it might skip some stuff.

Overall, its a valuable tool for performing static reverse engineering on malwares and any binary files. It is easy to use, and it can be used to dump all the outcome as text files, which makes it easy to further analyze the results and/or create a detailed report.























