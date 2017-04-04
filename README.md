# FrankenStrings Static Service

#### Licences

FIREEYE FLARE-FLOSS: See flarefloss.LICENSE.txt 

BALBUZARD: BSD 2-Clause Licence, see top of balbuzard code files

#### Service Details

NOTE: This service does not require you to buy any licence and is preinstalled and working after a default installation.

**When not in deep scan mode, this AL service will skip detection modules based on a submitted file's size 
(to prevent service backlog and service timeouts). The defaults are 
intentionally set at low sizes. Filters can be easily changed in the source code, in the 'execute' module, 
based on the amount of traffic/hardware your AL instance is running.**

This service does the following:

1. String Extraction:
    * executable/windows files:
        - FireEye Flare-FLOSS static strings modules (unicode and ascii). Matches IOC's only (see patterns.py)
        - FireEye Flare-FLOSS decoded strings modules
        - FireEye Flare-FLOSS stacked strings modules
    * other file types:
        - FireEye Flare-FLOSS static strings modules (unicode and ascii). Matches IOC's only (see patterns.py)
        - [DEEP SCAN ONLY] Balbuzard's bbcrack level 1 AND level 2 XOR transform modules. Matches specific IOCs only
         (see patterns.py, bbcrack.py) 
        - Base64Dump.py's string extract
        
        
2. File Extraction:
    * executable/windows files:
        - Balbuzard's bbcrack level 1 XOR transform modules. Searches for PE files only
        - [DEEP SCAN ONLY] Balbuzard's bbcrack level 1 AND level 2 XOR modules. Searches for PE files only
        - Base64Dump.py's B64 module search for file types of interest (see frankenstrings.py)       
    * other file types:
        - Base64Dump.py's B64 module search for file types of interest (see frankenstrings.py)
        - Unicode, Hex, Ascii-Hex extraction modules (for possible shellcode and rtf objdata objects)
        - Balbuzard's bbcrack level 1 XOR transform modules. Searches for PE files only
        - [DEEP SCAN ONLY] Balbuzard's bbcrack level 1 AND level 2 XOR modules. Searches for PE files only

#### Result Output
1. Static Strings (ASCII, UNICODE, BASE64):
    * Strings matching IOC patterns of interest [Result Text and Tag]
    * Decoded BASE64 Files [Extracted File]
2. Hex Strings:
    * Raw dumps of suspected shellcode data [Extracted File]
3. Decoded Strings:
    * All strings [Result Text and Tag]
    * Strings matching IOC patterns of interest [Tag]
4. Stacked Strings:
    * All strings, group by likeness [Result Text]
    * Strings matching IOC patterns of interest [Tag]
5. XOR Strings:
    * All strings matching IOC patterns of interest [Result Text and Tag]
    * Decoded XOR'd PE File [Extracted File]