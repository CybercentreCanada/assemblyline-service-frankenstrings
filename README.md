# FrankenStrings Static Service

#### Licences

FIREEYE FLARE-FLOSS: See flarefloss.LICENSE.txt 

BALBUZARD: BSD 2-Clause Licence, see top of balbuzard code files

#### Service Details

NOTE: This service does not require you to buy any licence and is preinstalled and working after a default installation.

This service does the following:

1. String Extraction:
    * executable/windows files:
        - FireEye Flare-FLOSS static strings modules (unicode and ascii). Matches IOC's only (see patterns.py)
        - FireEye Flare-FLOSS stacked strings modules
        - FireEye Flare-FLOSS decoded strings modules
    * other file types:
        - FireEye Flare-FLOSS static strings modules (unicode and ascii). Matches IOC's only (see patterns.py)
        - Balbuzard's bbcrack level 1 XOR transform modules
        - [DEEP SCAN ONLY] Balbuzard's bbcrack level 1 AND level 2 XOR transform modules (see patterns.py, bbcrack.py) *__No guarantee that the service will not timeout!__*

2. File Extraction:
    * executable/windows files:
        - Base64Dump.py's B64 module          
    * other file types:
        - Base64Dump.py's B64, Unicode and Hex modules
        - Ascii-hex extraction module
        - Balbuzard's bbcrack level 1 XOR transform modules for PE Header with file extraction

#### Result Output
1. Static Strings (ASCII, BASE64, HEX AND UNICODE):
    * Strings matching IOC patterns of interest (see patterns.py) [Result Text & Tag]
    * Decoded BASE64 PE File [Extracted File]
2. ASCII-HEX Data:
    * Raw dumps of suspected shellcode data [Extracted File]
3. Decoded Strings:
    * All strings [Result Text & Tag]
    * Strings matching IOC patterns of interest [Tag]
4. Stacked Strings:
    * All strings, group by likeness [Result Text]
    * Strings matching IOC patterns of interest (see patterns.py) [Tag]
5. XOR Strings:
    * All strings matching patterns of interest (see patterns.py) [Result Text]
    * Decoded XOR'd PE File [Extracted File]