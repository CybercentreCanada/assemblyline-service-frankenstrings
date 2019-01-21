"""
FrankenStrings Service
See README.md for details about this service.
"""
from assemblyline.al.service.base import ServiceBase
from assemblyline.al.common.heuristics import Heuristic
from assemblyline.common.net import is_valid_domain, is_valid_email
from assemblyline.al.common.result import Result, ResultSection, SCORE, TAG_TYPE, TAG_WEIGHT, TEXT_FORMAT
from assemblyline.common.timeout import alarm_clock
from textwrap import dedent

pefile = None
bbcrack = None
PatternMatch = None


class FrankenStrings(ServiceBase):
    SERVICE_CATEGORY = 'Static Analysis'
    SERVICE_ACCEPTS = '.*'
    SERVICE_DESCRIPTION = "Suspicious String Monster"
    SERVICE_REVISION = ServiceBase.parse_revision('$Id$')
    SERVICE_VERSION = '1'
    SERVICE_TIMEOUT = 300
    SERVICE_ENABLED = True
    SERVICE_CPU_CORES = 1
    SERVICE_RAM_MB = 256
    SERVICE_DEFAULT_CONFIG = {
        'MAX_SIZE': 3000000,
        'MAX_LENGTH': 5000,
        'ST_MAX_SIZE': 0,
        'BB_MAX_SIZE': 85000,
        'FF_MAX_SIZE': 85000,
        'FF_ENC_MIN_LENGTH': 7,
        'FF_STACK_MIN_LENGTH': 7
    }

    # Heuristics
    AL_FRANKENSTRINGS_001 = Heuristic("AL_FrankenStrings_001", "Base64_Decoded", "",
                                      dedent("""\
                                            Base64-like strings discovered and decoded. 
                                            """))
    AL_FRANKENSTRINGS_002 = Heuristic("AL_FrankenStrings_002", "XOR_decoded", "",
                                      dedent("""\
                                            XOR'd IOC content found and decoded
                                            """))
    AL_FRANKENSTRINGS_003 = Heuristic("AL_FrankenStrings_003", "Embedded_PE", "",
                                      dedent("""\
                                            Embedded PE extracted.
                                            """))
    AL_FRANKENSTRINGS_004 = Heuristic("AL_FrankenStrings_004", "Unicode_decoded", "",
                                      dedent("""\
                                            Unicode-like data found and decoded in non-exectuable file. 
                                            """))
    AL_FRANKENSTRINGS_005 = Heuristic("AL_FrankenStrings_005", "ASCIIhex_file_decoded", "",
                                      dedent("""\
                                            Possible ASCII hex encoded file decoded in non-executable file. 
                                            """))
    AL_FRANKENSTRINGS_006 = Heuristic("AL_FrankenStrings_006", "ASCIIhex_strings_decoded", "",
                                      dedent("""\
                                            ASCII hex-like strings found and decoded in non-executable file. 
                                            """))
    AL_FRANKENSTRINGS_007 = Heuristic("AL_FrankenStrings_007", "ASCIIhex_xor_string", "",
                                      dedent("""\
                                            Popssible ASCII hex-like string with additional xor encoding found.
                                            """))
    AL_FRANKENSTRINGS_008 = Heuristic("AL_FrankenStrings_008", "flare_encoded_string", "executable/",
                                      dedent("""\
                                            Encoded string found and decoded in executable file by Flare-Floss modules.
                                            """))
    AL_FRANKENSTRINGS_009 = Heuristic("AL_FrankenStrings_009", "flare_stacked_string", "executable/",
                                      dedent("""\
                                            Stacked string found and decoded in executable file by Flare-Floss modules. 
                                            """))
    AL_FRANKENSTRINGS_010 = Heuristic("AL_FrankenStrings_010", "code_file_deobfuscation", "code/",
                                      dedent("""\
                                            Partial code potentially deobfuscated by Crowbar module. 
                                            """))

    FILETYPES = [
        'application',
        'document',
        'exec',
        'image',
        'Microsoft',
        'text',
    ]

    HEXENC_STRINGS = [
        '\u',
        '%u',
        '\\x',
        '0x',
        '&H',  # hex notation in VBA
    ]

    def import_service_deps(self):
        global namedtuple, strings, binascii, hashlib, magic, mmap, os, re, string, unicodedata, \
            pefile, bbcrack, PatternMatch, CrowBar
        from collections import namedtuple
        from floss import strings
        import binascii
        import hashlib
        import magic
        import mmap
        import os
        import re
        import string
        import unicodedata
        import pefile
        from al_services.alsvc_frankenstrings.balbuzard.bbcrack import bbcrack
        from al_services.alsvc_frankenstrings.balbuzard.patterns import PatternMatch
        from al_services.alsvc_frankenstrings.misc_tools.crowbar import CrowBar

    def __init__(self, cfg=None):
        super(FrankenStrings, self).__init__(cfg)
        # Unless patterns are added/adjusted to patterns.py, the following should remain at 7:
        self.st_min_length = 7
        self.before = None

    def start(self):
        self.log.debug("FrankenStrings service started")

# --- Support Functions ------------------------------------------------------------------------------------------------

    def ioc_to_tag(self, data, patterns, res, taglist=False, check_length=False, strs_max_size=0,
                   st_max_length=300, savetoset=False):
        """Searches data for patterns and adds as AL tag to result output.

        Args:
            data: Data to be searched.
            patterns: FrankenStrings Patterns() object.
            res: AL result.
            taglist: True if tag list should be returned.
            check_length: True if length of string should be compared to st_max_length.
            strs_max_size: Maximum size of strings list. If greater then only network IOCs will be searched.
            st_max_length: Maximum length of a string from data that can be searched.
            savetoset: When True tag value will be saved to self.before (for Crowbar module).

        Returns:
            If tag list has been requested, returns tag list as dictionary. Otherwise returns None.

        """

        if taglist:
            tags = {}

        if check_length:
            ml = self.st_min_length
        else:
            ml = 4

        strs = set()
        jn = False

        # Flare-FLOSS ascii string extract
        for ast in strings.extract_ascii_strings(data, n=ml):
            if check_length:
                if len(ast.s) < st_max_length:
                    strs.add(ast.s)
            else:
                strs.add(ast.s)
        # Flare-FLOSS unicode string extract
        for ust in strings.extract_unicode_strings(data, n=ml):
            if check_length:
                if len(ust.s) < st_max_length:
                    strs.add(ust.s)
            else:
                strs.add(ust.s)

        if check_length:
            if len(strs) > strs_max_size:
                jn = True

        if len(strs) > 0:
            for s in strs:
                st_value = patterns.ioc_match(s, bogon_ip=True, just_network=jn)
                if len(st_value) > 0:
                    for ty, val in st_value.iteritems():
                        if taglist and ty not in tags:
                            tags[ty] = set()
                        if val == "":
                            asc_asc = unicodedata.normalize('NFKC', val).encode('ascii', 'ignore')
                            # For crowbar plugin
                            if savetoset:
                                self.before.add(asc_asc)
                            # Ensure AL will accept domain tags:
                            if ty == 'NET_DOMAIN_NAME':
                                if not is_valid_domain(asc_asc):
                                    continue
                            if ty == 'NET_EMAIL':
                                if not is_valid_email(asc_asc):
                                    continue
                            # 1000 is the maximum allowed size of an AL tag
                            if len(asc_asc) < 1001:
                                res.add_tag(TAG_TYPE[ty], asc_asc, TAG_WEIGHT.LOW)
                                if taglist:
                                    tags[ty].add(asc_asc)
                        else:
                            for v in val:
                                # For crowbar plugin
                                if savetoset:
                                    self.before.add(v)
                                if ty == 'NET_DOMAIN_NAME':
                                    if not is_valid_domain(v):
                                        continue
                                if ty == 'NET_EMAIL':
                                    if not is_valid_email(v):
                                        continue
                                if len(v) < 1001:
                                    res.add_tag(TAG_TYPE[ty], v, TAG_WEIGHT.LOW)
                                    if taglist:
                                        tags[ty].add(v)
        if taglist:
            return tags
        else:
            return

    @staticmethod
    def decode_bu(data, size):
        """ Adjusted 'base64dump.py' by Didier Stevens@https://DidierStevens.com. Convert ascii to hex.

        Args:
            data: Ascii string to be converted.
            size: Unit size.

        Returns:
            Decoded data.
        """
        decoded = ''

        if size == 2:
            while data != '':
                decoded += binascii.a2b_hex(data[2:4])
                data = data[4:]
        if size == 4:
            while data != '':
                decoded += binascii.a2b_hex(data[4:6]) + binascii.a2b_hex(data[2:4])
                data = data[6:]
        if size == 8:
            while data != '':
                decoded += binascii.a2b_hex(data[8:10]) + binascii.a2b_hex(data[6:8]) + \
                           binascii.a2b_hex(data[4:6]) + binascii.a2b_hex(data[2:4])
                data = data[10:]
        if size == 16:
            while data != '':
                decoded += binascii.a2b_hex(data[16:18]) + binascii.a2b_hex(data[14:16]) + \
                           binascii.a2b_hex(data[12:14]) + binascii.a2b_hex(data[10:12]) + \
                           binascii.a2b_hex(data[8:10]) + binascii.a2b_hex(data[6:8]) + \
                           binascii.a2b_hex(data[4:6]) + binascii.a2b_hex(data[2:4])
                data = data[18:]

        return decoded

    @staticmethod
    def unicode_longest_string(lisdata):
        """Compare sizes of unicode strings.

        Args:
            lisdata: A list of strings.

        Returns:
            Result of test: Do all strings match in length?
                If True, returns all strings combined.
                If False, returns longest string greater than 50 bytes.
                If no string lonfer than 50 bytes, returns empty string.
        """
        maxstr = len(max(lisdata, key=len))
        newstr = ""

        if all(len(i) == maxstr for i in lisdata):
            for i in lisdata:
                newstr += i
            return newstr
        elif maxstr > 50:
            return max(lisdata, key=len)
        else:
            return newstr

    def decode_encoded_udata(self, request, encoding, data):
        """Compare sizes of unicode strings. Some code taken from bas64dump.py @ https://DidierStevens.com.

        Args:
            request: AL request object (for submitting extracted files to AL when needed).
            encoding: Encoding string used (i.e. '0x').
            data: Data to be examined.

        Returns:
            List of hashes of extracted files submitted to AL and list of decoded unicode data information.
        """

        decoded_list = []
        shalist = []
        decoded_res = []

        qword = re.compile(r'(?:'+re.escape(encoding)+'[A-Fa-f0-9]{16})+')
        dword = re.compile(r'(?:'+re.escape(encoding)+'[A-Fa-f0-9]{8})+')
        word = re.compile(r'(?:'+re.escape(encoding)+'[A-Fa-f0-9]{4})+')
        by = re.compile(r'(?:'+re.escape(encoding)+'[A-Fa-f0-9]{2})+')

        qbu = re.findall(qword, data)
        if len(qbu) > 0:
            qlstr = self.unicode_longest_string(qbu)
            if len(qlstr) > 50:
                decoded_list.append((self.decode_bu(qlstr, size=16), qlstr[:200]))
        dbu = re.findall(dword, data)
        if len(dbu) > 0:
            dlstr = self.unicode_longest_string(dbu)
            if len(dlstr) > 50:
                decoded_list.append((self.decode_bu(dlstr, size=8), dlstr[:200]))
        wbu = re.findall(word, data)
        if len(wbu) > 0:
            wlstr = self.unicode_longest_string(wbu)
            if len(wlstr) > 50:
                decoded_list.append((self.decode_bu(wlstr, size=4), wlstr[:200]))
        bbu = re.findall(by, data)
        if len(bbu) > 0:
            blstr = self.unicode_longest_string(bbu)
            if len(blstr) > 50:
                decoded_list.append((self.decode_bu(blstr, size=2), blstr[:200]))

        filtered_list = filter(lambda x: len(x[0]) > 30, decoded_list)

        for decoded in filtered_list:
            uniq_char = ''.join(set(decoded[0]))
            if len(decoded[0]) >= 500:
                if len(uniq_char) > 20:
                    sha256hash = hashlib.sha256(decoded[0]).hexdigest()
                    shalist.append(sha256hash)
                    udata_file_path = os.path.join(self.working_directory, "{0}_enchex_{1}_decoded"
                                               .format(sha256hash[0:10], encoding))
                    request.add_extracted(udata_file_path, "Extracted unicode file during FrankenStrings analysis.")
                    with open(udata_file_path, 'wb') as unibu_file:
                        unibu_file.write(decoded[0])
                        self.log.debug("Submitted dropped file for analysis: %s" % udata_file_path)
            else:
                if len(uniq_char) > 6:
                    decoded_res.append((hashlib.sha256(decoded[0]).hexdigest(), len(decoded), decoded[1], decoded[0]))

        return shalist, decoded_res

    # Base64 Parse
    def b64(self, request, b64_string, patterns, res):
        """Decode B64 data. Select code taken from bas64dump.py @ https://DidierStevens.com.

        Args:
            request: AL request object (for submitting extracted files to AL when needed).
            b64_string: Possible base64 string.
            patterns: FrankenStrings Patterns() object.
            res: AL result object.

        Returns:
            List of result information.
        """
        results = {}
        if len(b64_string) >= 16 and len(b64_string) % 4 == 0:
            try:
                base64data = binascii.a2b_base64(b64_string)
                sha256hash = hashlib.sha256(base64data).hexdigest()
                # Search for embedded files of interest
                if 200 < len(base64data) < 10000000:
                    m = magic.Magic(mime=True)
                    mag = magic.Magic()
                    ftype = m.from_buffer(base64data)
                    mag_ftype = mag.from_buffer(base64data)
                    for ft in self.FILETYPES:
                        if (ft in ftype and not 'octet-stream' in ftype) or ft in mag_ftype:
                            b64_file_path = os.path.join(self.working_directory, "{}_b64_decoded"
                                                     .format(sha256hash[0:10]))
                            request.add_extracted(b64_file_path, "Extracted b64 file during FrankenStrings analysis.")
                            with open(b64_file_path, 'wb') as b64_file:
                                b64_file.write(base64data)
                                self.log.debug("Submitted dropped file for analysis: %s" % b64_file_path)

                            results[sha256hash] = [len(b64_string), b64_string[0:50],
                                                   "[Possible file contents. See extracted files.]", ""]
                            return results

                # See if any IOCs in decoded data
                pat = self.ioc_to_tag(base64data, patterns, res, taglist=True)
                # Filter printable characters then put in results
                asc_b64 = "".join(i for i in base64data if 31 < ord(i) < 127)
                # If data has less then 7 uniq chars then ignore
                uniq_char = ''.join(set(asc_b64))
                if len(uniq_char) > 6 and len(re.sub("\s", "", asc_b64)) > 14:
                    results[sha256hash] = [len(b64_string), b64_string[0:50], asc_b64, base64data]
                # If not all printable characters but IOCs discovered, extract to file
                elif len(pat) > 0:
                    b64_file_path = os.path.join(self.working_directory, "{}_b64_decoded"
                                                 .format(sha256hash[0:10]))
                    request.add_extracted(b64_file_path, "Extracted b64 file during FrankenStrings analysis.")
                    with open(b64_file_path, 'wb') as b64_file:
                        b64_file.write(base64data)
                        self.log.debug("Submitted dropped file for analysis: %s" % b64_file_path)

                    results[sha256hash] = [len(b64_string), b64_string[0:50],
                                           "[IOCs discovered with other non-printable data. "
                                           "See extracted files.]", ""]

            except Exception:
                return results
        return results

    def unhexlify_ascii(self, request, data, tag, patterns, res):
        """Plain ascii hex conversion.

        Args:
            request: AL request object (for submitting extracted files to AL when needed).
            data: Data to examine.
            tag: AL request.tag (file type string).
            patterns: Frankenstrings Patterns() object.
            res: AL result object.

        Returns:
            List of result information.
        """
        filefound = False
        tags = {}
        if len(data) % 2 != 0:
            data = data[:-1]
        try:
            binstr = binascii.unhexlify(data)
        except Exception:
            return filefound, tags
        # If data has less than 7 uniq chars return
        uniq_char = ''.join(set(binstr))
        if len(uniq_char) < 7:
            return filefound, tags
        # If data is greater than 500 bytes create extracted file
        if len(binstr) > 500:
            if len(uniq_char) < 20:
                return filefound, tags
            filefound = True
            sha256hash = hashlib.sha256(binstr).hexdigest()
            ascihex_file_path = os.path.join(self.working_directory, "{}_asciihex_decoded"
                                                 .format(sha256hash[0:10]))
            request.add_extracted(ascihex_file_path, "Extracted ascii-hex file during FrankenStrings analysis.")
            with open(ascihex_file_path, 'wb') as fh:
                    fh.write(binstr)
            return filefound, tags
        # Else look for patterns
        tags = self.ioc_to_tag(binstr, patterns, res, taglist=True, st_max_length=1000)
        if len(tags) > 0:
            return filefound, tags
        # Else look for small XOR encoded strings in code files
        if 20 < len(binstr) <= 128 and tag.startswith('code/'):
            xresult = bbcrack(binstr, level='small_string')
            if len(xresult) > 0:
                for transform, regex, match in xresult:
                    if regex.startswith('EXE_'):
                        tags['BB_PESTUDIO_BLACKLIST_STRING'] = {data: [match, transform]}
                    else:
                        tags["BB_{}" .format(regex)] = {data: [match, transform]}
                    return filefound, tags
        return filefound, tags

    # Executable extraction
    def pe_dump(self, request, temp_file, offset, fn, msg, fail_on_except=False):
        """Use PEFile application to find the end of the file (biggest section length wins).

        Args:
            request: AL request object (for submitting extracted PE AL).
            temp_file: Sample file with possible embedded PE.
            offset: Offset of temp_file where PE file begins.
            fn: String appended to extracted PE file name.
            fail_on_except: When False, if PEFile fails, extract from offset all the way to the end of the initial file.

        Returns:
            True if PE extracted.
        """
        pe_extract = None
        try:
            with open(temp_file, "rb") as f:
                mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)

            pedata = mm[offset:]

            try:
                peinfo = pefile.PE(data=pedata)
                lsize = 0
                #pefile.PE()
                for section in peinfo.sections:
                    size = section.PointerToRawData + section.SizeOfRawData
                    if size > lsize:
                        lsize = size
                if lsize > 0:
                    pe_extract = pedata[0:lsize]
                else:
                    if not fail_on_except:
                        pe_extract = pedata
            except Exception:
                if not fail_on_except:
                    pe_extract = pedata

            if pe_extract:
                pe_file_path = os.path.join(self.working_directory, "{0}_{1}"
                                            .format(hashlib.sha256(pe_extract).hexdigest()[0:10], fn))
                request.add_extracted(pe_file_path, "{}" .format(msg))
                with open(pe_file_path, 'wb') as exe_file:
                    exe_file.write(pe_extract)
                    self.log.debug("Submitted dropped file for analysis: %s" % pe_file_path)
        finally:
            try:
                mm.close()
                if pe_extract:
                    return True
                else:
                    return False
            except:
                if pe_extract:
                    return True
                else:
                    return False

    # Flare Floss Methods:
    @staticmethod
    def sanitize_string_for_printing(s):
        """
        Copyright FireEye Labs
        Extracted code from FireEye Flare-Floss source code found here:
        http://github.com/fireeye/flare-floss
        Return sanitized string for printing.
        :param s: input string
        :return: sanitized string
        """
        try:
            sanitized_string = s.encode('unicode_escape')
            sanitized_string = sanitized_string.replace('\\\\', '\\')  # print single backslashes
            sanitized_string = "".join(c for c in sanitized_string if c in string.printable)
            return sanitized_string
        except:
            return

    @staticmethod
    def filter_unique_decoded(decoded_strings):
        """
        Copyright FireEye Labs
        Extracted code from FireEye Flare-Floss source code found here:
        http://github.com/fireeye/flare-floss
        """
        try:
            unique_values = set()
            originals = []
            for decoded in decoded_strings:
                hashable = (decoded.va, decoded.s, decoded.decoded_at_va, decoded.fva)
                if hashable not in unique_values:
                    unique_values.add(hashable)
                    originals.append(decoded)
            return originals
        except:
            return
        
    @staticmethod
    def decode_strings(vw, function_index, decoding_functions_candidates):
        """
        Copyright FireEye Labs
        Extracted code from FireEye Flare-Floss source code found here:
        http://github.com/fireeye/flare-floss
        FLOSS string decoding algorithm
        :param vw: vivisect workspace
        :param function_index: function data
        :param decoding_functions_candidates: identification manager
        :return: list of decoded strings ([DecodedString])
        """
        decoded_strings = []

        try:
            with alarm_clock(60):
                from floss import string_decoder
                for fva, _ in decoding_functions_candidates:
                    for ctx in string_decoder.extract_decoding_contexts(vw, fva):
                        for delta in string_decoder.emulate_decoding_routine(vw, function_index, fva, ctx):
                            for delta_bytes in string_decoder.extract_delta_bytes(delta, ctx.decoded_at_va, fva):
                                for decoded_string in string_decoder.extract_strings(delta_bytes):
                                    decoded_strings.append(decoded_string)
        except:
            pass
        finally:
            return decoded_strings or None

    @staticmethod
    def get_all_plugins():
        """
        Copyright FireEye Labs
        Extracted code from FireEye Flare-Floss source code found here:
        http://github.com/fireeye/flare-floss
        Return all plugins to be run.
        """
        try:
            from floss.interfaces import DecodingRoutineIdentifier
            from floss.plugins import arithmetic_plugin, function_meta_data_plugin, library_function_plugin
            ps = DecodingRoutineIdentifier.implementors()
            if len(ps) == 0:
                ps.append(function_meta_data_plugin.FunctionCrossReferencesToPlugin())
                ps.append(function_meta_data_plugin.FunctionArgumentCountPlugin())
                ps.append(function_meta_data_plugin.FunctionIsThunkPlugin())
                ps.append(function_meta_data_plugin.FunctionBlockCountPlugin())
                ps.append(function_meta_data_plugin.FunctionInstructionCountPlugin())
                ps.append(function_meta_data_plugin.FunctionSizePlugin())
                ps.append(function_meta_data_plugin.FunctionRecursivePlugin())
                ps.append(library_function_plugin.FunctionIsLibraryPlugin())
                ps.append(arithmetic_plugin.XORPlugin())
                ps.append(arithmetic_plugin.ShiftPlugin())
            return ps
        except:
            return

# --- Execute ----------------------------------------------------------------------------------------------------------

    def execute(self, request):
        """ Main Module. See README for details."""
        result = Result()
        request.result = result
        patterns = PatternMatch()
        # For crowbar plugin
        self.before = set()
        sample_type = request.tag
        # Filters for submission modes. Listed in order of use.
        if request.deep_scan:
            # Maximum size of submitted file to run this service:
            max_size = 8000000
            # String length maximum
            # Used in basic ASCII and UNICODE modules:
            max_length = 1000000
            # String list maximum size
            # List produced by basic ASCII and UNICODE module results and will determine
            # if patterns.py will only evaluate network IOC patterns:
            st_max_size = 1000000
            # BBcrack maximum size of submitted file to run module:
            bb_max_size = 200000
            # Flare Floss  maximum size of submitted file to run encoded/stacked string modules:
            ff_max_size = 200000
            # Flare Floss minimum string size for encoded/stacked string modules:
            ff_enc_min_length = 7
            ff_stack_min_length = 7
        else:
            max_size = self.cfg.get('MAX_SIZE', self.SERVICE_DEFAULT_CONFIG['MAX_SIZE'])
            max_length = self.cfg.get('MAX_LENGTH', self.SERVICE_DEFAULT_CONFIG['MAX_LENGTH'])
            st_max_size = self.cfg.get('ST_MAX_SIZE', self.SERVICE_DEFAULT_CONFIG['ST_MAX_SIZE'])
            bb_max_size = self.cfg.get('BB_MAX_SIZE', self.SERVICE_DEFAULT_CONFIG['BB_MAX_SIZE'])
            ff_max_size = self.cfg.get('FF_MAX_SIZE', self.SERVICE_DEFAULT_CONFIG['FF_MAX_SIZE'])
            ff_enc_min_length = self.cfg.get('FF_ENC_MIN_LENGTH', self.SERVICE_DEFAULT_CONFIG['FF_ENC_MIN_LENGTH'])
            ff_stack_min_length = self.cfg.get('FF_STACK_MIN_LENGTH',
                                               self.SERVICE_DEFAULT_CONFIG['FF_STACK_MIN_LENGTH'])

        # Begin analysis
        if (request.task.size or 0) < max_size and not sample_type.startswith("archive/"):
            # Generate section in results set
            from floss import decoding_manager
            from floss import identification_manager as im, stackstrings
            from fuzzywuzzy import process
            from tabulate import tabulate
            import viv_utils

            b64_al_results = []
            encoded_al_results = []
            encoded_al_tags = set()
            stacked_al_results = []
            xresult = []
            xor_al_results = []
            unicode_al_results = {}
            unicode_al_dropped_results = []
            asciihex_file_found = False
            asciihex_dict = {}
            asciihex_bb_dict = {}
            embedded_pe = False
            cb_code_res = None
            cb_decoded_data = None
            cb_filex = None

# --- Generate Results -------------------------------------------------------------------------------------------------
            # Static strings -- all sample types
            alfile = request.download()
            res = (ResultSection(SCORE.NULL, "FrankenStrings Detected Strings of Interest:",
                                 body_format=TEXT_FORMAT.MEMORY_DUMP))

            with open(alfile, "rb") as f:
                file_data = f.read()

            # Find ASCII & Unicode IOC Strings
            # Find all patterns if the file is identified as code (for crowbar plugin)
            if sample_type.startswith('code'):
                chkl = False
                svse = True
            else:
                chkl = True
                svse = False
            file_plainstr_iocs = self.ioc_to_tag(file_data, patterns, res, taglist=True, check_length=chkl,
                                                 strs_max_size=st_max_size, st_max_length=max_length, savetoset=svse)

            # Embedded executable -- all sample types
            # PE Strings
            pat_exedos = r'(?s)This program cannot be run in DOS mode'
            pat_exeheader = r'(?s)MZ.{32,1024}PE\000\000.+'

            for pos_exe in re.findall(pat_exeheader, file_data[1:]):
                if re.search(pat_exedos, pos_exe):
                    pe_sha256 = hashlib.sha256(pos_exe).hexdigest()
                    temp_file = os.path.join(self.working_directory, "EXE_TEMP_{}".format(pe_sha256))

                    with open(temp_file, 'wb') as pedata:
                        pedata.write(pos_exe)

                    embedded_pe = self.pe_dump(request, temp_file, offset=0, fn="embed_pe",
                                               msg="PE header strings discovered in sample")

            # Possible encoded strings -- all sample types except code/* (code will be handled by crowbar plugin)
            # Find Base64 encoded strings and files of interest
            if not sample_type.startswith('code'):
                # Base64 characters with possible space, newline characters and HTML line feeds (&#(XA|10);)
                for b64_match in re.findall('([\x20]{0,2}(?:[A-Za-z0-9+/]{10,}={0,2}'
                                            '(?:&#[x1][A0];){0,1}[\r]?[\n]?){2,})', file_data):
                    b64_string = b64_match.replace('\n', '').replace('\r', '').replace(' ', '').replace('&#xA;', '')\
                        .replace('&#10;', '')
                    uniq_char = ''.join(set(b64_string))
                    if len(uniq_char) > 6:
                        b64result = self.b64(request, b64_string, patterns, res)
                        if len(b64result) > 0:
                            b64_al_results.append(b64result)

                # UTF-16 strings
                for ust in strings.extract_unicode_strings(file_data, n=self.st_min_length):
                    for b64_match in re.findall('([\x20]{0,2}(?:[A-Za-z0-9+/]{10,}={0,2}[\r]?[\n]?){2,})', ust.s):
                        b64_string = b64_match.decode('utf-8').replace('\n', '').replace('\r', '').replace(' ', '')
                        uniq_char = ''.join(set(b64_string))
                        if len(uniq_char) > 6:
                            b64result = self.b64(request, b64_string, patterns, res)
                            if len(b64result) > 0:
                                b64_al_results.append(b64result)

                # Balbuzard's bbcrack XOR'd strings to find embedded patterns/PE files of interest
                if (request.task.size or 0) < bb_max_size:
                    if request.deep_scan:
                        xresult = bbcrack(file_data, level=2)
                    else:
                        xresult = bbcrack(file_data, level=1)

                    xindex = 0
                    for transform, regex, offset, score, smatch in xresult:
                        if regex == 'EXE_HEAD':
                            xindex += 1
                            xtemp_file = os.path.join(self.working_directory, "EXE_HEAD_{0}_{1}_{2}.unXORD"
                                                      .format(xindex, offset, score))
                            with open(xtemp_file, 'wb') as xdata:
                                xdata.write(smatch)
                            pe_extracted = self.pe_dump(request, xtemp_file, offset, fn="xorpe_decoded",
                                         msg="Extracted xor file during FrakenStrings analysis.")
                            if pe_extracted:
                                xor_al_results.append('%-20s %-7s %-7s %-50s' % (str(transform), offset, score,
                                                                                 "[PE Header Detected. "
                                                                                 "See Extracted files]"))
                        else:
                            xor_al_results.append('%-20s %-7s %-7s %-50s' % (str(transform), offset, score, smatch))

            # Other possible encoded strings -- all sample types but code and executables
            if not sample_type.split('/', 1)[0] in ['executable', 'code']:
                # Unicode/Hex Strings
                for hes in self.HEXENC_STRINGS:
                    hes_regex = re.compile(re.escape(hes) + '[A-Fa-f0-9]{2}')
                    if re.search(hes_regex, file_data) is not None:
                        uhash, unires = self.decode_encoded_udata(request, hes, file_data)
                        if len(uhash) > 0:
                            for usha in uhash:
                                unicode_al_dropped_results.append('{0}_{1}' .format(usha, hes))
                        if len(unires) > 0:
                            for i in unires:
                                unicode_al_results[i[0]] = [i[1], i[2], i[3]]

                # Go over again, looking for long ASCII-HEX character strings
                hex_pat = re.compile('((?:[0-9a-fA-F]{2}[\r]?[\n]?){16,})')
                for hex_match in re.findall(hex_pat, file_data):
                    hex_string = hex_match.replace('\r', '').replace('\n', '')
                    afile_found, asciihex_results = self.unhexlify_ascii(request, hex_string, request.tag, patterns,
                                                                         res)
                    if afile_found:
                        asciihex_file_found = True
                    if asciihex_results != "":
                        for ask, asi in asciihex_results.iteritems():
                            if ask.startswith('BB_'):
                                # Add any xor'd content to its own result set
                                ask = ask.split('_', 1)[1]
                                if ask not in asciihex_bb_dict:
                                    asciihex_bb_dict[ask] = []
                                asciihex_bb_dict[ask].append(asi)
                            else:
                                if ask not in asciihex_dict:
                                    asciihex_dict[ask] = []
                                asciihex_dict[ask].append(asi)

            # Encoded/Stacked strings -- Windows executable sample types
            if (request.task.size or 0) < ff_max_size and sample_type.startswith("executable/windows/"):

                m = magic.Magic()
                file_magic = m.from_buffer(file_data)

                if not file_magic.endswith("compressed"):
                    try:
                        vw = viv_utils.getWorkspace(alfile, should_save=False)
                    except:
                        vw = False

                    if vw:
                        try:
                            selected_functions = set(vw.getFunctions())
                            selected_plugins = self.get_all_plugins()

                            # Encoded strings
                            decoding_functions_candidates = im.identify_decoding_functions(vw, selected_plugins,
                                                                                       selected_functions)
                            candidates = decoding_functions_candidates.get_top_candidate_functions(10)
                            function_index = viv_utils.InstructionFunctionIndex(vw)
                            decoded_strings = self.decode_strings(vw, function_index, candidates)
                            decoded_strings = self.filter_unique_decoded(decoded_strings)

                            long_strings = filter(lambda l_ds: len(l_ds.s) >= ff_enc_min_length, decoded_strings)

                            for ds in long_strings:
                                s = self.sanitize_string_for_printing(ds.s)
                                if ds.characteristics["location_type"] == decoding_manager.LocationType.STACK:
                                    offset_string = "[STACK]"
                                elif ds.characteristics["location_type"] == decoding_manager.LocationType.HEAP:
                                    offset_string = "[HEAP]"
                                else:
                                    offset_string = hex(ds.va or 0)
                                encoded_al_results.append((offset_string, hex(ds.decoded_at_va), s))
                                encoded_al_tags.add(s)

                            # Stacked Strings
                            # s.s = stacked string
                            # s.fva = Function
                            # s.frame_offset = Frame Offset
                            stack_strings = list(set(stackstrings.extract_stackstrings(vw, selected_functions)))
                            # Final stacked result list
                            if len(stack_strings) > 0:
                                # Filter min string length
                                extracted_strings = \
                                    list(filter(lambda l_s: len(l_s.s) >= ff_stack_min_length, stack_strings))

                                # Set up list to ensure stacked strings are not compared twice
                                picked = set()
                                # Create namedtuple for groups of like-stacked strings
                                al_tuples = namedtuple('Group', 'stringl funoffl')

                                # Create set of stacked strings for fuzzywuzzy to compare
                                choices = set()
                                for s in extracted_strings:
                                    choices.add(s.s)

                                # Begin Comparison
                                for s in extracted_strings:
                                    if s.s in picked:
                                        pass
                                    else:
                                        # Add stacked string to used-value list (picked)
                                        picked.add(s.s)
                                        # Create lists for 'strings' and 'function:frame offset' results
                                        sstrings = []
                                        funoffs = []
                                        # Append initial stacked string tuple values to lists
                                        indexnum = 1
                                        sstrings.append('{0}:::{1}' .format(indexnum, s.s.encode()))
                                        funoffs.append('{0}:::{1}:{2}' .format(indexnum, hex(s.fva),
                                                                               hex(s.frame_offset)))
                                        # Use fuzzywuzzy process module to compare initial stacked string to remaining
                                        # stack string values
                                        like_ss = process.extract(s.s, choices, limit=50)

                                        if len(like_ss) > 0:
                                            # Filter scores in like_ss with string compare scores less than 75
                                            filtered_likess = filter(lambda ls: ls[1] > 74, like_ss)
                                            if len(filtered_likess) > 0:
                                                for likestring in filtered_likess:
                                                    for subs in extracted_strings:
                                                        if subs == s or subs.s != likestring[0]:
                                                            pass
                                                        else:
                                                            indexnum += 1
                                                            # Add all similar strings to picked list and remove from
                                                            # future comparison list (choices)
                                                            picked.add(subs.s)
                                                            if subs.s in choices:
                                                                choices.remove(subs.s)
                                                            # For all similar stacked strings add values to lists
                                                            sstrings.append('{0}:::{1}' .format(indexnum,
                                                                                                subs.s.encode()))
                                                            funoffs.append('{0}:::{1}:{2}'
                                                                           .format(indexnum, hex(subs.fva),
                                                                                   hex(subs.frame_offset)))

                                        # Remove initial stacked string from comparison list (choices)
                                        if s.s in choices:
                                            choices.remove(s.s)
                                        # Create namedtuple to add to final results
                                        fuzresults = al_tuples(stringl=sstrings, funoffl=funoffs)
                                        # Add namedtuple to final result list
                                        stacked_al_results.append(fuzresults)
                        except Exception:
                            pass

            # Static decoding of code files
            if sample_type.startswith('code'):
                cb = CrowBar()
                if request.deep_scan:
                    max_attempts = 100
                else:
                    max_attempts = 5
                cb_code_res, cb_decoded_data, cb_filex = cb.hammertime(max_attempts, file_data, self.before, patterns,
                                                                       self.working_directory)

# --- Store Results ----------------------------------------------------------------------------------------------------

            if len(file_plainstr_iocs) > 0 \
                    or len(b64_al_results) > 0 \
                    or len(xor_al_results) > 0 \
                    or len(encoded_al_results) > 0 \
                    or len(stacked_al_results) > 0 \
                    or len(unicode_al_results) > 0 or len(unicode_al_dropped_results) > 0\
                    or asciihex_file_found or len(asciihex_dict) > 0 or len(asciihex_bb_dict)\
                    or cb_code_res:

                # Report ASCII String Results
                if len(file_plainstr_iocs) > 0:
                    ascii_res = (ResultSection(SCORE.NULL, "FLARE FLOSS Plain IOC Strings:",
                                               body_format=TEXT_FORMAT.MEMORY_DUMP,
                                               parent=res))
                    for k, l in sorted(file_plainstr_iocs.iteritems()):
                        for i in sorted(l):
                            ascii_res.add_line("Found %s string: %s" % (k.replace("_", " "), i))

                # Report B64 Results
                if len(b64_al_results) > 0:
                    result.report_heuristic(FrankenStrings.AL_FRANKENSTRINGS_001)
                    b64_ascii_content = []
                    b64_res = (ResultSection(SCORE.LOW, "Base64 Strings:", parent=res))
                    b64index = 0
                    for b64dict in b64_al_results:
                        for b64k, b64l in b64dict.iteritems():
                            b64index += 1
                            sub_b64_res = (ResultSection(SCORE.NULL, "Result {}" .format(b64index), parent=b64_res))
                            sub_b64_res.add_line('BASE64 TEXT SIZE: {}' .format(b64l[0]))
                            sub_b64_res.add_line('BASE64 SAMPLE TEXT: {}[........]' .format(b64l[1]))
                            sub_b64_res.add_line('DECODED SHA256: {}'.format(b64k))
                            subb_b64_res = (ResultSection(SCORE.NULL, "DECODED ASCII DUMP:",
                                                          body_format=TEXT_FORMAT.MEMORY_DUMP, parent=sub_b64_res))
                            subb_b64_res.add_line('{}' .format(b64l[2]))
                            if b64l[2] not in ["[Possible file contents. See extracted files.]",
                                               "[IOCs discovered with other non-printable data. See extracted files.]"]:
                                b64_ascii_content.append(b64l[2])
                    # Write all non-extracted decoded b64 content to file
                    if len(b64_ascii_content) > 0:
                        all_b64 = "\n".join(b64_ascii_content)
                        b64_all_sha256 = hashlib.sha256(all_b64).hexdigest()
                        b64_file_path = os.path.join(self.working_directory, b64_all_sha256)
                        try:
                            with open(b64_file_path, 'wb') as fh:
                                fh.write(all_b64)
                            request.add_extracted(b64_file_path, "all misc decoded b64 from sample", "all_b64_{}.txt"
                                                  .format(b64_all_sha256[:7]))
                        except Exception as e:
                            self.log.error("Error while adding extracted"
                                           " b64 content: {}: {}".format(b64_file_path, str(e)))

                # Report XOR embedded results
                # Result Graph:
                if len(xor_al_results) > 0:
                    result.report_heuristic(FrankenStrings.AL_FRANKENSTRINGS_002)
                    x_res = (ResultSection(SCORE.VHIGH, "BBCrack XOR'd Strings:", body_format=TEXT_FORMAT.MEMORY_DUMP,
                                           parent=res))
                    xformat_string = '%-20s %-7s %-7s %-50s'
                    xcolumn_names = ('Transform', 'Offset', 'Score', 'Decoded String')
                    x_res.add_line(xformat_string % xcolumn_names)
                    x_res.add_line(xformat_string % tuple(['-' * len(s) for s in xcolumn_names]))
                    for xst in xor_al_results:
                        x_res.add_line(xst)
                # Result Tags:
                for transform, regex, offset, score, smatch in xresult:
                    if not regex.startswith("EXE_"):
                        res.add_tag(TAG_TYPE[regex], smatch, TAG_WEIGHT.LOW)
                        res.add_tag(TAG_TYPE[regex], smatch, TAG_WEIGHT.LOW)

                # Report Embedded PE
                if embedded_pe:
                    result.report_heuristic(FrankenStrings.AL_FRANKENSTRINGS_003)
                    res.add_section(ResultSection(SCORE.HIGH, "Embedded PE header discovered in sample. "
                                                              "See extracted files."))

                # Report Unicode Encoded Data:
                if len(unicode_al_results) > 0 or len(unicode_al_dropped_results) > 0:
                    result.report_heuristic(FrankenStrings.AL_FRANKENSTRINGS_004)
                    unicode_emb_res = (ResultSection(SCORE.NULL, "Found Unicode-Like Strings in Non-Executable:",
                                                     body_format=TEXT_FORMAT.MEMORY_DUMP,
                                                     parent=res))

                    if len(unicode_al_results) > 0:
                        unires_index = 0
                        for uk, ui in unicode_al_results.iteritems():
                            unires_index += 1
                            sub_uni_res = (ResultSection(SCORE.LOW, "Result {}".format(unires_index),
                                                          parent=unicode_emb_res))
                            sub_uni_res.add_line('ENCODED TEXT SIZE: {}'.format(ui[0]))
                            sub_uni_res.add_line('ENCODED SAMPLE TEXT: {}[........]'.format(ui[1]))
                            sub_uni_res.add_line('DECODED SHA256: {}'.format(uk))
                            subb_uni_res = (ResultSection(SCORE.NULL, "DECODED ASCII DUMP:",
                                                          body_format=TEXT_FORMAT.MEMORY_DUMP,
                                                          parent=sub_uni_res))
                            subb_uni_res.add_line('{}'.format(ui[2]))
                            # Look for IOCs of interest
                            hits = self.ioc_to_tag(ui[2], patterns, res, st_max_length=1000, taglist=True)
                            if len(hits) > 0:
                                sub_uni_res.score += 490
                                subb_uni_res.add_line("Suspicious string(s) found in decoded data.")

                    if len(unicode_al_dropped_results) > 0:
                        for ures in unicode_al_dropped_results:
                            uhas = ures.split('_')[0]
                            uenc = ures.split('_')[1]
                            unicode_emb_res.score += 50
                            unicode_emb_res.add_line("Extracted over 50 bytes of possible embedded unicode with {0} "
                                                     "encoding. SHA256: {1}. See extracted files." .format(uenc, uhas))
                # Report Ascii Hex Encoded Data:
                if asciihex_file_found:
                    result.report_heuristic(FrankenStrings.AL_FRANKENSTRINGS_005)
                    asciihex_emb_res = (ResultSection(SCORE.MED, "Found Large Ascii Hex Strings in Non-Executable:",
                                                      body_format=TEXT_FORMAT.MEMORY_DUMP,
                                                      parent=res))
                    asciihex_emb_res.add_line("Extracted possible ascii-hex object(s). See extracted files.")

                if len(asciihex_dict) > 0:
                    result.report_heuristic(FrankenStrings.AL_FRANKENSTRINGS_006)
                    if request.tag.startswith("document"):
                        ascore = SCORE.LOW
                    else:
                        ascore = SCORE.VHIGH
                    asciihex_res = (ResultSection(ascore, "ASCII HEX DECODED IOC Strings:",
                                                  body_format=TEXT_FORMAT.MEMORY_DUMP,
                                                  parent=res))
                    for k, l in sorted(asciihex_dict.iteritems()):
                        for i in l:
                            for ii in i:
                                asciihex_res.add_line("Found %s decoded HEX string: %s" % (k.replace("_", " "), ii))

                if len(asciihex_bb_dict) > 0:
                    result.report_heuristic(FrankenStrings.AL_FRANKENSTRINGS_007)
                    asciihex_res = (ResultSection(SCORE.VHIGH, "ASCII HEX AND XOR DECODED IOC Strings:",
                                                  parent=res))
                    xindex = 0
                    for k, l in sorted(asciihex_bb_dict.iteritems()):
                        for i in l:
                            for kk, ii in i.iteritems():
                                xindex += 1
                                asx_res = (ResultSection(SCORE.NULL, "Result {}" .format(xindex),
                                                         parent=asciihex_res))
                                asx_res.add_line("Found %s decoded HEX string, masked with transform %s:"
                                                 % (k.replace("_", " "), ii[1]))
                                asx_res.add_line("Decoded XOR string:")
                                asx_res.add_line(ii[0])
                                asx_res.add_line("Original ASCII HEX String:")
                                asx_res.add_line(kk)
                                res.add_tag(TAG_TYPE[k], ii[0], TAG_WEIGHT.LOW)

                # Store Encoded String Results
                if len(encoded_al_results) > 0:
                    result.report_heuristic(FrankenStrings.AL_FRANKENSTRINGS_008)
                    encoded_res = (ResultSection(SCORE.LOW, "FLARE FLOSS Decoded Strings:",
                                                 body_format=TEXT_FORMAT.MEMORY_DUMP,
                                                 parent=res))
                    encoded_res.add_line(tabulate(encoded_al_results, headers=["Offset", "Called At", "String"]))
                    # Create AL tag for each unique decoded string
                    for st in encoded_al_tags:
                        res.add_tag(TAG_TYPE['FILE_DECODED_STRING'], st[0:75], TAG_WEIGHT.LOW)
                        # Create tags for strings matching indicators of interest
                        if len(st) >= self.st_min_length:
                            hits = self.ioc_to_tag(st, patterns, res, st_max_length=1000, taglist=True)
                            if len(hits) > 0:
                                encoded_res.score = 500
                                encoded_res.add_line("Suspicious string(s) found in decoded data.")

                # Report Stacked String Results
                if len(stacked_al_results) > 0:
                    result.report_heuristic(FrankenStrings.AL_FRANKENSTRINGS_009)
                    # No score on these as there are many FPs
                    stacked_res = (ResultSection(SCORE.NULL, "FLARE FLOSS Stacked Strings:",
                                                 body_format=TEXT_FORMAT.MEMORY_DUMP, parent=res))
                    for s in sorted(stacked_al_results):
                        groupname = re.sub(r'^[0-9]+:::', '', min(s.stringl, key=len))
                        group_res = (ResultSection(SCORE.NULL, "Group:'{0}' Strings:{1}" .format(groupname,
                                                                                                 len(s.stringl)),
                                                   body_format=TEXT_FORMAT.MEMORY_DUMP, parent=stacked_res))
                        group_res.add_line("String List:\n{0}\nFunction:Offset List:\n{1}"
                                           .format(re.sub(r'(^\[|\]$)', '', str(s.stringl)),
                                                   re.sub(r'(^\[|\]$)', '', str(s.funoffl))))
                        # Create tags for strings matching indicators of interest
                        for st in s.stringl:
                            extract_st = re.sub(r'^[0-9]+:::', '', st)
                            if len(extract_st) >= self.st_min_length:
                                hits = self.ioc_to_tag(extract_st, patterns, res, st_max_length=1000, taglist=True)
                                if len(hits) > 0:
                                    group_res.score = 500
                                    group_res.add_line("Suspicious string(s) found in decoded data.")

                # Report Crowbar de-obfuscate results and add deob code to result
                if cb_code_res:
                    result.report_heuristic(FrankenStrings.AL_FRANKENSTRINGS_010)
                    res.add_section(cb_code_res)
                    decodefp = os.path.join(self.working_directory, "{}_decoded".format(request.md5))
                    request.add_extracted(decodefp, "Debofuscated sample")
                    with open(decodefp, 'wb') as dcf:
                        dcf.write(cb_decoded_data)
                        self.log.debug("Submitted dropped file for analysis: {}" .format(decodefp))
                    for f in cb_filex:
                        request.add_extracted(f, "Debofuscated file of interest extracted from sample")

                result.add_result(res)
