# Static Reverse Engineering [SRE] tool
Static Reverse Engineering &lt;the complete command-line tool>


The command line tool is designed to conduct static analysis on binary files, such as malware samples, to gather valuable information without executing the file. It offers a comprehensive set of analysis techniques and generates text files containing the outcomes for further analysis or report creation.

_**Key Features:**_

**Static Analysis:** The tool performs static analysis, which means it examines the binary file without executing or running it. This helps in understanding the characteristics and potential behavior of the file.

**Text File based Output:** The tool saves the analysis outcome as text file. This format is chosen to facilitate easy access, review, and further analysis of the collected information. It allows analysts to search, filter, and process the data conveniently.  Also very helpful to write custom 'Yara rules'.

**200+ Checkpoints:** The tool encompasses 90 different checkpoints categorized into nine distinct categories. These checkpoints cover a wide range of analysis techniques, aiming to provide a comprehensive data of the binary file.

**Categories of Analysis:**
  **Integrity Analyse
  Metadata Analyse
  Packer Detection
  Api Analyse
  String Analyse
  IoC Extraction => 
  Malicious Behaviour Analyse 
  Disasmembly Dump
  VirusTotal Check**  _Note: this will not submit the samples to VT._

By performing a thorough analysis across these nine categories and 200+ checkpoints, the tool aims to provide a comprehensive understanding of the binary file's characteristics, behavior, and potential risks.


The tool is a command line tool that can be used to perform static reverse engineering on malwares and any binary files. It can be used to perform a complete static analysis on the binary file, and it will dump all the outcome as text files in the analysis_result_<binaryfile> folder. The tool has capabilities to check all the following 90 checkpoints under 9 categories:
Imports and exports
Functions and procedures
Data structures
Control flow
Memory management
Encoding
Debugging
Optimization
Miscellaneous
All the outcome saved as text files as it would much easier for further analysis and/or create detailed report.

**Here are some of the advantages of using this tool:**
It can be used to perform a complete static analysis on the binary file, which can help to identify potential malicious code.

It can be used to dump all the outcome as text files, which makes it easy to further analyze the results and/or create a detailed report.

It is a command line tool, which makes it easy to use and automate.

**Here are some of the limitations of this tool:**
It is a static analysis tool, which means that it cannot analyze the dynamic behavior of the malware.
It is not a perfect tool, and it may miss some malicious code.
It can be time-consuming to use, especially for large binary files.
Overall, this tool is a valuable tool for performing static reverse engineering on malwares and any binary files. It is easy to use, and it can be used to dump all the outcome as text files, which makes it easy to further analyze the results and/or create a detailed report. However, it is important to remember that it is a static analysis tool, and it cannot analyze the dynamic behavior of the malware.

