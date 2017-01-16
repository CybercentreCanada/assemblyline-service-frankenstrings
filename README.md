# FrankenStrings Static Service

### Licences

FIREEYE FLARE-FLOSS:    See flarefloss.LICENSE.txt
BALBUZARD:              BSD 2-Clause Licence, see top of balbuzard code files

### Service Details
This service does the following:
    1. String Extraction:
            * executable/windows files:
                FireEye Flare-FLOSS static strings modules (unicode and ascii). Matches IOC's only (see patterns.py)
                FireEye Flare-FLOSS stacked strings modules
                FireEye Flare-FLOSS decoded strings modules
            * other file types:
                FireEye Flare-FLOSS static strings modules (unicode and ascii). Matches IOC's only (see patterns.py)
                Base64Dump.py's B64, Unicode and Hex modules
                Ascii-hex module
                Balbuzard's bbcrack level 1 XOR transform modules (see patterns.py). Matches IOC's only (see patterns.py)

    2. File Extraction:
            * all file types:
                Base64 string module for PE Header with file extraction
                Balbuzard's bbcrack level 1 XOR transform modules for PE Header with file extraction

### Result Output
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