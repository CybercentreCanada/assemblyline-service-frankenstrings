# FrankenStrings Static Service

#### Licences

FIREEYE FLARE-FLOSS: See flarefloss/LICENSE.txt 

BALBUZARD: BSD 2-Clause Licence, see top of balbuzard code files

#### Service Details

NOTE: This service does not require you to buy any licence and is preinstalled and working after a default installation.

**When not in deep scan mode, this AL service will skip detection modules based on a submitted file's size 
(to prevent service backlog and timeouts). The defaults are
intentionally set at low sizes. Filters can be easily changed in the service configuration,
based on the amount of traffic/hardware your AL instance is running.**

- MAX_SIZE: Maximum size of submitted file for this service.
- MAX_LENGTH: String length maximum. Used in basic ASCII and UNICODE modules.
- ST_MAX_SIZE: String list maximum size. List produced by basic ASCII and
UNICODE module results, and will determine if patterns.py will only evaluate network IOC patterns.
- BB_MAX_SIZE: BBcrack maximum size of submitted file to run module.
- FF_MAX_SIZE: Flare Floss  maximum size of submitted file to run encoded/stacked string modules.
- FF_ENC_MIN_LENGTH/FF_STACK_MIN_LENGTH: Flare Floss minimum string size for encoded/stacked
string modules to show in results.

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
    * other file types (except code/*):
        - Base64Dump.py's B64 module search for file types of interest (see frankenstrings.py)
        - Unicode, Hex, Ascii-Hex extraction modules (for possible shellcode and rtf objdata objects)
        - Balbuzard's bbcrack level 1 XOR transform modules. Searches for PE files only
        - [DEEP SCAN ONLY] Balbuzard's bbcrack level 1 AND level 2 XOR modules. Searches for PE files only

3. Code/* File Type Evaluation:
    * Attempts to de-obfuscate IOC values from code samples by iterating 5x (100x deep scan) through the following
     modules in crowbar.py:
        1. VBE Decode
        2. Concat strings
        3. MSWord macro vars
        4. Powershell vars
        5. String replace
        6. Powershell carets
        7. Array of strings
        8. Fake array vars
        9. Reverse strings
        10. B64 Decode
        11. Simple XOR function
        12. Charcode
        13. Charcode hex

#### Result Output
1. Static Strings (ASCII, UNICODE, BASE64):
    * Strings matching IOC patterns of interest [Result Text and Tag]
    * Decoded BASE64. Extract content over 200 bytes, otherwise combine all decoded content and extract in single text file.  [Extracted File OR Result Text and Tag]
2. ASCII Hex Strings:
    * Content extraction of ascii hex data successfully decoded (any RTF objdata or data over 500 bytes) 
    [Extracted File]
    * IOC pattern matching for any successfully decoded data [Result Text and Tag]
    * URI pattern matching after custom brute force xor module (see bbcrack.py for added module)
    [Result Text and Tag]
3. FF Decoded Strings:
    * All strings [Result Text and Tag]
    * Strings matching IOC patterns of interest [Tag]
4. FF Stacked Strings:
    * All strings, group by likeness (determined by fuzzywuzzy library) [Result Text]
    * Strings matching IOC patterns of interest [Tag]
5. BBCrack XOR Strings:
    * All strings matching IOC patterns of interest [Result Text and Tag]
    * Decoded XOR'd PE File [Extracted File]
6. CrowBar Decoded Strings:
    * All IOC strings discovered [Result Text and Tag]
    * Decoded B64 content over 500 bytes [Extracted File] 
