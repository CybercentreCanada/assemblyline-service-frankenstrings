# FrankenStrings Service

NOTE: This service does not require you to buy any licence and is preinstalled and working after a default installation.

**When not in deep scan mode, this AL service will skip detection modules based on a submitted file's size 
(to prevent service backlog and timeouts). The defaults are
intentionally set at low sizes. Filters can be easily changed in the service configuration,
based on the amount of traffic/hardware your AL instance is running.**

#### Service Configuration

- max_size: Maximum size of submitted file for this service
- max_length: String length maximum. Used in basic ASCII and UNICODE modules
- st_max_size: String list maximum size. List produced by basic ASCII and UNICODE module results, and will determine if patterns.py will only evaluate network IOC patterns
- bb_max_size: BBcrack maximum size of submitted file to run module

#### Service Details

1. String Extraction:
    * ASCII and unicode string IOC checking. (see patterns.py)
    * Balbuzard's bbcrack level 1 (*level 2 for deep scan*) XOR transform modules. Matches specific IOCs only (see patterns.py, bbcrack.py) 
    * Base64 string extract
        
2. File Extraction:
    * Balbuzard's bbcrack level 1 (*level 2 for deep scan*) XOR transform modules. (Searches for PE files only)
    * Base64 module search for file types of interest (see frankenstrings.py)
    * Embedded PE file extraction
    * Unicode, Hex, Ascii-Hex extraction modules (for possible shellcode)

#### Result Output
1. Static Strings (ASCII, UNICODE, BASE64):
    * Tag strings matching IOC patterns of interest
    * Decoded BASE64. Extract content over 200 bytes, otherwise combine all decoded content and extract in single text file
2. Embedded PE files:
    * Extract PE files embedded in the file
    * Extract reversed PE files embedded in the file
3. ASCII Hex Strings:
    * Content extraction of ascii hex data successfully decoded (any data over 500 bytes)
    * Tag IOC pattern matching for any successfully decoded data
    * Tag URI pattern matching after custom brute force xor module (see bbcrack.py for added module)
4. BBCrack XOR Strings:
    * Tag all strings matching IOC patterns of interest
    * Extract decoded XOR'd PE File

#### Licences

FIREEYE FLARE-FLOSS: See flarefloss/LICENSE.txt 

BALBUZARD: BSD 2-Clause Licence, see top of balbuzard code files

