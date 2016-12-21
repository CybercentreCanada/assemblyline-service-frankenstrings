"""
Licences:
FIREEYE FLARE-FLOSS: See flarefloss.LICENSE.txt
BALBUZARD: BSD 2-Clause Licence, see top of code

This service does the following:
    1. String Extraction:
            -executable/windows files:
                FireEye Flare-FLOSS static strings modules (unicode and ascii)
                FireEye Flare-FLOSS stacked strings modules
                FireEye Flare-FLOSS decoded strings modules
            -other file types:
                FireEye Flare-FLOSS static strings modules (unicode and ascii)
                Base64Dump.py B64, Unicode and Hex modules
                Balbuzard's bbcrack level 1 XOR transform modules search for IOC patterns (see patterns.py)

    2. File Extraction:
            -all file types:
                Base64 string module for PE Header with file extraction
                Balbuzard's bbcrack level 1 XOR transform modules for PE Header with file extraction

Result Output:
        1. Static Strings (ASCII, BASE64, HEX AND UNICODE):
            - Strings matching IOC patterns of interest (see patterns.py) [Result Text & Tag]
            - Decoded BASE64 PE File [Extracted File]
        2. Decoded Strings:
            - All strings [Result Text & Tag]
            - Strings matching IOC patterns of interest [Tag]
        3. Stacked Strings:
            - All strings, group by likeness [Result Text]
            - Strings matching IOC patterns of interest (see patterns.py) [Tag]
        4. XOR Strings:
            - All strings matching bbcrack stage 2 patterns of interest (see patterns.py) [Result Text]
            - Decoded XOR'd PE File [Extracted File]
"""
from assemblyline.al.service.base import ServiceBase   #, skip_low_scoring
from assemblyline.al.common.result import Result, ResultSection, SCORE, TAG_TYPE, TAG_WEIGHT, TEXT_FORMAT
from al_services.alsvc_frankenstrings.balbuzard.bbcrack import bbcrack
from al_services.alsvc_frankenstrings.balbuzard.patterns import PatternMatch
from collections import namedtuple
import binascii
import hashlib
import magic
import mmap
import os
import string
import re


class FrankenStrings(ServiceBase):
    SERVICE_CATEGORY = 'Test'
    SERVICE_ACCEPTS = '.*'
    SERVICE_DESCRIPTION = "FireEye Labs Obfuscated String Solver"
    SERVICE_REVISION = ServiceBase.parse_revision('$Id: 398318d7de75fbe1786289b7d45ba625bf4231aa $')
    SERVICE_VERSION = '1'
    SERVICE_TIMEOUT = 300
    SERVICE_ENABLED = True
    SERVICE_CPU_CORES = 1
    SERVICE_RAM_MB = 256

    #Use the following for live streaming:
    #SERVICE_STAGE = 'SECONDARY'
    #@staticmethod
    #def skip(task):
        #return skip_low_scoring(task)

    def import_service_deps(self):
        global pefile
        import pefile

    def __init__(self, cfg=None):
        super(FrankenStrings, self).__init__(cfg)
        self.tagtypes = ['FILE_NAME',
                         'FILE_PDB_STRING',
                         'NET_EMAIL',
                         'NET_FULL_URI',
                         'NET_DOMAIN_NAME',
                         'NET_IP',
                         'PESTUDIO_BLACKLIST_STRING',
                         'REGISTRY_KEY',
                         'WIN_API_STRING',]
        self.filetypes = ['exec',
                          ]

    def start(self):
        self.log.debug("FLOSS service started")

# --- Support Functions ------------------------------------------------------------------------------------------------
    # base64dump.py Methods:

    # CIC: Call If Callable
    @staticmethod
    def CIC(expression):
        """
        From 'base64dump.py' by Didier Stevens@https://DidierStevens.com
        """
        if callable(expression):
            return expression()
        else:
            return expression

    # IFF: IF Function
    @classmethod
    def IFF(cls, expression, valueTrue, valueFalse):
        """
        From 'base64dump.py' by Didier Stevens@https://DidierStevens.com
        """
        if expression:
            return cls.CIC(valueTrue)
        else:
            return cls.CIC(valueFalse)

    # Ascii Dump
    @classmethod
    def AsciiDump(cls, data):
        return ''.join([cls.IFF(ord(b) >= 32, b, '.') for b in data])

    @staticmethod
    def DecodeBU(data, size):
        """
        Adjusted to take in to account byte, word, dword, qword
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

        maxstr = len(max(lisdata, key=len))
        newstr = ""

        # Test if all (if by chance the data was separated by a character --i.e. ','--).
        # if true, combine all data and return string,
        # else return longest string if greater than 50 bytes,
        # else return empty string

        if all(len(i) == maxstr for i in lisdata):
            for i in lisdata:
                newstr += i
            return  newstr
        elif maxstr > 50:
            return maxstr
        else:
            return newstr


    @classmethod
    # '\u'
    def DecodeDataBU(cls, data):
        """
        Adjusted code in base64decode.py to take in to account byte, word, dword, qword
        """
        decoded_list = []
        decoded = ''
        largest_str = ''

        qbu = re.findall(r'(?:\\u[ABCDEFabcdef0123456789]{16})+', data)
        if len(qbu) > 0:
            qlstr = cls.unicode_longest_string(qbu)
            if cls.unicode_longest_string(qbu) != '':
                decoded_list.append(cls.DecodeBU(qlstr, size=16))
        dbu = re.findall(r'(?:\\u[ABCDEFabcdef0123456789]{8})+', data)
        if len(dbu) > 0:
            dlstr = cls.unicode_longest_string(dbu)
            if cls.unicode_longest_string(dbu) != '':
                decoded_list.append(cls.DecodeBU(dlstr, size=8))
        wbu = re.findall(r'(?:\\u[ABCDEFabcdef0123456789]{4})+', data)
        if len(wbu) > 0:
            wlstr = cls.unicode_longest_string(wbu)
            if cls.unicode_longest_string(wbu) != '':
                decoded_list.append(cls.DecodeBU(wlstr, size=4))
        bbu = re.findall(r'(?:\\u[ABCDEFabcdef0123456789]{2})+', data)
        if len(bbu) > 0:
            blstr = cls.unicode_longest_string(bbu)
            if cls.unicode_longest_string(bbu) != '':
                decoded_list.append(cls.DecodeBU(blstr, size=2))

        if len(decoded_list) > 0:
            largest_str = max(decoded_list, key=len)

        if len(largest_str) > 50:
            decoded = largest_str

        return decoded

    @classmethod
    # '\u'
    def DecodeDataPU(cls, data):
        """
        Adjusted code in base64decode.py to take in to account byte, word, dword, qword
        """
        decoded_list = []
        decoded = ''
        largest_str = ''

        qbu = re.findall(r'(?:%u[ABCDEFabcdef0123456789]{16})+', data)
        if len(qbu) > 0:
            qlstr = cls.unicode_longest_string(qbu)
            if cls.unicode_longest_string(qbu) != '':
                decoded_list.append(cls.DecodeBU(qlstr, size=16))
        dbu = re.findall(r'(?:%u[ABCDEFabcdef0123456789]{8})+', data)
        if len(dbu) > 0:
            dlstr = cls.unicode_longest_string(dbu)
            if cls.unicode_longest_string(dbu) != '':
                decoded_list.append(cls.DecodeBU(dlstr, size=8))
        wbu = re.findall(r'(?:%u[ABCDEFabcdef0123456789]{4})+', data)
        if len(wbu) > 0:
            wlstr = cls.unicode_longest_string(wbu)
            if cls.unicode_longest_string(wbu) != '':
                decoded_list.append(cls.DecodeBU(wlstr, size=4))
        bbu = re.findall(r'(?:%u[ABCDEFabcdef0123456789]{2})+', data)
        if len(bbu) > 0:
            blstr = cls.unicode_longest_string(bbu)
            if cls.unicode_longest_string(bbu) != '':
                decoded_list.append(cls.DecodeBU(blstr, size=2))

        if len(decoded_list) > 0:
            largest_str = max(decoded_list, key=len)

        if len(largest_str) > 50:
            decoded = largest_str

        return decoded

    @classmethod
    # '0x'
    def DecodeData0X(cls, data):
        """
        Using some selected code from 'base64dump.py' by Didier Stevens@https://DidierStevens.com
        """
        decoded = ''
        decoded_list = []
        largest_str = ''

        qbu = re.findall(r'(?:0x[ABCDEFabcdef0123456789]{16})+', data)
        if len(qbu) > 0:
            qlstr = cls.unicode_longest_string(qbu)
            if cls.unicode_longest_string(qbu) != '':
                decoded_list.append(cls.DecodeBU(qlstr, size=16))
        dbu = re.findall(r'(?:0x[ABCDEFabcdef0123456789]{8})+', data)
        if len(dbu) > 0:
            dlstr = cls.unicode_longest_string(dbu)
            if cls.unicode_longest_string(dbu) != '':
                decoded_list.append(cls.DecodeBU(dlstr, size=8))
        wbu = re.findall(r'(?:0x[ABCDEFabcdef0123456789]{4})+', data)
        if len(wbu) > 0:
            wlstr = cls.unicode_longest_string(wbu)
            if cls.unicode_longest_string(wbu) != '':
                decoded_list.append(cls.DecodeBU(wlstr, size=4))
        bbu = re.findall(r'(?:0x[ABCDEFabcdef0123456789]{2})+', data)
        if len(bbu) > 0:
            blstr = cls.unicode_longest_string(bbu)
            if cls.unicode_longest_string(bbu) != '':
                decoded_list.append(cls.DecodeBU(blstr, size=2))

        if len(decoded_list) > 0:
            largest_str = max(decoded_list, key=len)

        if len(largest_str) > 50:
            decoded = largest_str

        return decoded

    @classmethod
    # '\x'
    def DecodeData2FX(cls, data):
        """
        Using some selected code from 'base64dump.py' by Didier Stevens@https://DidierStevens.com
        """
        decoded = ''
        decoded_list = []
        largest_str = ''

        qbu = re.findall(r'(?:\\x[ABCDEFabcdef0123456789]{16})+', data)
        if len(qbu) > 0:
            qlstr = cls.unicode_longest_string(qbu)
            if cls.unicode_longest_string(qbu) != '':
                decoded_list.append(cls.DecodeBU(qlstr, size=16))
        dbu = re.findall(r'(?:\\x[ABCDEFabcdef0123456789]{8})+', data)
        if len(dbu) > 0:
            dlstr = cls.unicode_longest_string(dbu)
            if cls.unicode_longest_string(dbu) != '':
                decoded_list.append(cls.DecodeBU(dlstr, size=8))
        wbu = re.findall(r'(?:\\x[ABCDEFabcdef0123456789]{4})+', data)
        if len(wbu) > 0:
            wlstr = cls.unicode_longest_string(wbu)
            if cls.unicode_longest_string(wbu) != '':
                decoded_list.append(cls.DecodeBU(wlstr, size=4))
        bbu = re.findall(r'(?:\\x[ABCDEFabcdef0123456789]{2})+', data)
        if len(bbu) > 0:
            blstr = cls.unicode_longest_string(bbu)
            if cls.unicode_longest_string(bbu) != '':
                decoded_list.append(cls.DecodeBU(blstr, size=2))

        if len(decoded_list) > 0:
            largest_str = max(decoded_list, key=len)

        if len(largest_str) > 50:
            decoded = largest_str

        return decoded

    # Base64 Parse
    def b64(self, request, b64_string):
        """
        Using some selected code from 'base64dump.py' by Didier Stevens@https://DidierStevens.com
        """
        results = 0
        tags = 0
        if len(b64_string) >= 16 and len(b64_string) % 4 == 0:
            try:
                base64data = binascii.a2b_base64(b64_string)
                # Search for embedded files of interest
                if 1000 < len(base64data) < 2000000:
                    m = magic.Magic(mime=True)
                    ftype = m.from_buffer(base64data)
                    for ft in self.filetypes:
                        if ft in ftype:
                            b64_file_path = os.path.join(self.working_directory,
                                                         "{}_b64_decoded" .format(hashlib.md5(base64data).hexdigest()))
                            request.add_extracted(b64_file_path, "Extracted b64 file during FrankenStrings analysis.")
                            with open(b64_file_path, 'wb') as b64_file:
                                b64_file.write(base64data)
                                self.log.debug("Submitted dropped file for analysis: %s" % b64_file_path)
                            results = ('%-7d %-50s %-60s %-32s' % (len(b64_string),
                                                                   "Omitted",
                                                                   "[Possible {0} file contents, See extracted files.]"
                                                                   .format(ft),  hashlib.md5(base64data).hexdigest()))
                            return results, tags
                if isinstance(base64data, str):
                    results = ('%-7d %-50s %-60s %-32s' % (len(b64_string), b64_string[0:40],
                                                           self.AsciiDump(base64data[0:40]),
                                                           hashlib.md5(base64data).hexdigest()))
                    tags = (self.AsciiDump(base64data))
            except:
                return results, tags
        return results, tags

    def pe_dump(self, request, temp_file, offset):
        """
        Use PEFile application to find the end of the file (biggest section length wins). Else if PEFile fails, extract
        from offset all the way to the end of the initial file (granted, this is uglier).
        """
        with open(temp_file, "rb") as f:
            mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)

        pedata = mm[offset:]

        try:
            peinfo = pefile.PE(data=pedata)
            lsize = 0
            pefile.PE()
            for section in peinfo.sections:
                size = section.PointerToRawData + section.SizeOfRawData
                if size > lsize:
                    lsize = size
            if lsize > 0:
                pe_extract = pedata[0:lsize]
            else:
                pe_extract = mm
        except:
            #print pefile.PEFormatError
            pe_extract = mm

        xpe_file_path = os.path.join(self.working_directory, "{}_xorpe_decoded"
                                     .format(hashlib.md5(pe_extract).hexdigest()))
        request.add_extracted(xpe_file_path, "Extracted xor file during FrakenStrings analysis.")
        with open(xpe_file_path, 'wb') as b64_file:
            b64_file.write(pe_extract)
            self.log.debug("Submitted dropped file for analysis: %s" % xpe_file_path)

        mm.close()
        return

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
        sanitized_string = s.encode('unicode_escape')
        sanitized_string = sanitized_string.replace('\\\\', '\\')  # print single backslashes
        sanitized_string = "".join(c for c in sanitized_string if c in string.printable)
        return sanitized_string

    @staticmethod
    def filter_unique_decoded(decoded_strings):
        """
        Copyright FireEye Labs
        Extracted code from FireEye Flare-Floss source code found here:
        http://github.com/fireeye/flare-floss
        """
        unique_values = set()
        originals = []
        for decoded in decoded_strings:
            hashable = (decoded.va, decoded.s, decoded.decoded_at_va, decoded.fva)
            if hashable not in unique_values:
                unique_values.add(hashable)
                originals.append(decoded)
        return originals

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
        from floss import string_decoder
        decoded_strings = []
        # TODO pass function list instead of identification manager
        for fva, _ in decoding_functions_candidates.get_top_candidate_functions(10):
            for ctx in string_decoder.extract_decoding_contexts(vw, fva):
                for delta in string_decoder.emulate_decoding_routine(vw, function_index, fva, ctx):
                    for delta_bytes in string_decoder.extract_delta_bytes(delta, ctx.decoded_at_va, fva):
                        for decoded_string in string_decoder.extract_strings(delta_bytes):
                            decoded_strings.append(decoded_string)
        return decoded_strings

    @staticmethod
    def get_all_plugins():
        """
        Copyright FireEye Labs
        Extracted code from FireEye Flare-Floss source code found here:
        http://github.com/fireeye/flare-floss
        Return all plugins to be run.
        """
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

# --- Execute ----------------------------------------------------------------------------------------------------------

    def execute(self, request):
        """
        Main Module.
        Some code below is extracted from main.py from FireEye Labs Flare-FLOSS code found here:
        http://github.com/fireeye/flare-floss
        Runs FlOSS modules on file and creates AL result
        """
        result = Result()
        request.result = result
        if (request.task.size or 0) < 2000000:
            # Generate section in results set
            from floss import decoding_manager
            from floss import identification_manager as im, strings, stackstrings
            from fuzzywuzzy import process
            from tabulate import tabulate
            import viv_utils
            import unicodedata

            result_found = False
            unicode_found = False

            alfile = request.download()
            st_min_length = 5
            st_max_length = 301

            ascii_al_results = []
            b64_al_results = []
            b64_al_tags = set()
            xor_al_results = []
            unicode_al_results = []
            encoded_al_results = []
            encoded_al_tags = set()
            stacked_al_results = []

# --- Generate Results -------------------------------------------------------------------------------------------------

            # Static strings -- all file types

            with open(alfile, "rb") as f:
                orig_submitted_file = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
                file_data = f.read()

            # FLOSS string extract
            for s in strings.extract_ascii_strings(orig_submitted_file, n=st_min_length):
                if len(s.s) < st_max_length:
                    ascii_al_results.append(s.s)

            for s in strings.extract_unicode_strings(orig_submitted_file, n=st_min_length):
                if len(s.s) < st_max_length:
                    unicode_al_results.append(s.s)

            orig_submitted_file.close()

            # Unicode/Hex Strings -- Not executable files

            if not request.tag.startswith("executable/"):

                # base64dump.py unicode extract
                bu_uni_decoded = self.DecodeDataBU(file_data)
                if bu_uni_decoded != '':
                    unicode_found = True
                    unibu_file_path = os.path.join(self.working_directory, "{}_unibu_decoded"
                                                   .format(hashlib.md5(bu_uni_decoded).hexdigest()))
                    request.add_extracted(unibu_file_path, "Extracted \u_unicode file during FrankenStrings analysis.")
                    with open(unibu_file_path, 'wb') as unibu_file:
                        unibu_file.write(bu_uni_decoded)
                        self.log.debug("Submitted dropped file for analysis: %s" % unibu_file_path)

                pu_uni_decoded = self.DecodeDataPU(file_data)
                if pu_uni_decoded != '':
                    unicode_found = True
                    unipu_file_path = os.path.join(self.working_directory, "{}_unipu_decoded"
                                                   .format(hashlib.md5(pu_uni_decoded).hexdigest()))
                    request.add_extracted(unipu_file_path, "Extracted %u_unicode file during FrankenStrings analysis.")
                    with open(unipu_file_path, 'wb') as unipu_file:
                        unipu_file.write(pu_uni_decoded)
                        self.log.debug("Submitted dropped file for analysis: %s" % unipu_file_path)

                x_uni_decoded = self.DecodeData0X(file_data)
                if x_uni_decoded != '':
                    unicode_found = True
                    unix_file_path = os.path.join(self.working_directory, "{}_unix_decoded"
                                                   .format(hashlib.md5(x_uni_decoded).hexdigest()))
                    request.add_extracted(unix_file_path, "Extracted 0x_unicode file during FrankenStrings analysis.")
                    with open(unix_file_path, 'wb') as unix_file:
                        unix_file.write(x_uni_decoded)
                        self.log.debug("Submitted dropped file for analysis: %s" % unix_file_path)

                fx_uni_decoded = self.DecodeData2FX(file_data)
                if fx_uni_decoded != '':
                    unicode_found = True
                    unifx_file_path = os.path.join(self.working_directory, "{}_unifx_decoded"
                                                   .format(hashlib.md5(fx_uni_decoded).hexdigest()))
                    request.add_extracted(unifx_file_path, "Extracted /x_unicode file during FrankenStrings analysis.")
                    with open(unifx_file_path, 'wb') as unifx_file:
                        unifx_file.write(fx_uni_decoded)
                        self.log.debug("Submitted dropped file for analysis: %s" % unifx_file_path)


            # Encoded/Stacked strings -- Windows executable file types
            if request.tag.startswith("executable/windows/"):

                try:
                    vw = viv_utils.getWorkspace(alfile, should_save=False)
                except Exception, e:
                    self.log.exception('VIV Utils getWorkspace failed: {0}' .format(e.message))
                    return

                selected_functions = set(vw.getFunctions())
                selected_plugins = self.get_all_plugins()
                ds_min_length = 5
                al_min_length = 6

                # Encoded strings

                decoding_functions_candidates = im.identify_decoding_functions(vw, selected_plugins, selected_functions)
                function_index = viv_utils.InstructionFunctionIndex(vw)
                decoded_strings = self.decode_strings(vw, function_index, decoding_functions_candidates)
                decoded_strings = self.filter_unique_decoded(decoded_strings)

                long_strings = filter(lambda ds: len(ds.s) >= ds_min_length, decoded_strings)

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
                    extracted_strings = list(filter(lambda s: len(s.s) >= al_min_length, stack_strings))

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
                            funoffs.append('{0}:::{1}:{2}' .format(indexnum, hex(s.fva), hex(s.frame_offset)))
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
                                                # Add all similar strings to picked list and remove from future
                                                # comparison list (choices)
                                                picked.add(subs.s)
                                                if subs.s in choices:
                                                    choices.remove(subs.s)
                                                # For all similar stacked strings add values to lists
                                                sstrings.append('{0}:::{1}' .format(indexnum, subs.s.encode()))
                                                funoffs.append('{0}:::{1}:{2}' .format(indexnum, hex(subs.fva),
                                                                                       hex(subs.frame_offset)))

                            # Remove initial stacked string from comparison list (choices)
                            if s.s in choices:
                                choices.remove(s.s)
                            # Create namedtuple to add to final results
                            fuzresults = al_tuples(stringl=sstrings, funoffl=funoffs)
                            # Add namedtuple to final result list
                            stacked_al_results.append(fuzresults)

            # XOR'd strings to find embedded patterns/files of interest (seperate from Flare Floss plugin)
            if request.tag.startswith("executable/windows/"):
                xresult = bbcrack(file_data, level=1, exe=True)
            else:
                xresult = bbcrack(file_data, level=1)

            xindex = 0

            for transform, regex, offset, score, smatch in xresult:
                if regex == 'EXE_HEAD':
                    xindex += 1
                    xtemp_file = os.path.join(self.working_directory, "EXE_HEAD_{0}_{1}_{2}.unXORD"
                                              .format(xindex, offset, score))
                    xdata = open(xtemp_file, 'wb')
                    xdata.write(smatch)
                    xdata.close()
                    self.pe_dump(request, xtemp_file, offset)
                    xor_al_results.append('%-20s %-7s %-7s %-50s' % (str(transform), offset, score,
                                                                     "[PE Header Detected. See Extracted files]"))
                else:
                    xor_al_results.append('%-20s %-7s %-7s %-50s' % (str(transform), offset, score, smatch))

# --- Store Results ----------------------------------------------------------------------------------------------------

            if len(ascii_al_results) > 0 \
                    or len(unicode_al_results) > 0 \
                    or len(encoded_al_results) > 0 \
                    or len(stacked_al_results) > 0 \
                    or len(xor_al_results) > 0 \
                    or unicode_found:

                res = (ResultSection(SCORE.LOW, "FLARE FLOSS Detected Strings of Interest:",
                                     body_format=TEXT_FORMAT.MEMORY_DUMP))
                patterns = PatternMatch()

                # Store ASCII String Results
                if len(ascii_al_results) > 0:
                    ascii_dict = {}
                    for ast in ascii_al_results:
                        st_value = patterns.ioc_match(ast, bogon_ip=True)
                        if len(st_value) > 0:
                            for ty, val in st_value.iteritems():
                                if ty in self.tagtypes:
                                    if val == "":
                                        asc_asc = unicodedata.normalize('NFKC', val).encode('ascii', 'ignore')
                                        ascii_dict.setdefault(ty, set()).add(asc_asc)
                                        res.add_tag(TAG_TYPE[ty], asc_asc, TAG_WEIGHT.LOW)
                                    else:
                                        for v in val:
                                            ascii_dict.setdefault(ty, set()).add(v)
                                            res.add_tag(TAG_TYPE[ty], v, TAG_WEIGHT.LOW)

                    if len(ascii_dict) > 0:
                        result_found = True
                        ascii_res = (ResultSection(SCORE.NULL, "FLARE FLOSS ASCII IOC Strings:",
                                                   body_format=TEXT_FORMAT.MEMORY_DUMP,
                                                   parent=res))
                        for k, l in sorted(ascii_dict.iteritems()):
                            for i in sorted(l):
                                ascii_res.add_line("Found %s string: %s" % (k.replace("_", " "), i))

                    # Find Base64 ASCII and files of interest
                    # Base64 by single line:
                    for astr in ascii_al_results:
                        for b64_string in re.findall('[A-Za-z0-9+/]+={0,2}', astr):
                            b64result, b64tag = self.b64(request, b64_string)
                            if b64result != 0:
                                b64_al_results.append(b64result)
                            if b64tag != 0:
                                b64_al_tags.add(self.AsciiDump(b64tag))

                    # Base64 separated by newline characters
                    for b64_tuple in re.findall('(([A-Za-z0-9+/]+={0,2}[\n])+)', file_data):
                        b64_string = b64_tuple[0].replace('\n', '')
                        b64result, b64tag = self.b64(request, b64_string)
                        if b64result != 0:
                            b64_al_results.append(b64result)
                        if b64tag != 0:
                            b64_al_tags.add(self.AsciiDump(b64tag))

                    if len(b64_al_results) > 0:
                        b64_res = (ResultSection(SCORE.NULL, "FLARE FLOSS ASCII Base64 Strings:",
                                                 body_format=TEXT_FORMAT.MEMORY_DUMP,
                                                 parent=res))
                        result_found = True
                        # Add b64 table header to results
                        bformatstring = '%-7s %-50s %-60s %-32s'
                        bcolumnnames = ('Size', 'BASE64', 'Decoded', 'MD5 of Decoded Data')
                        b64_res.add_line(bformatstring % bcolumnnames)
                        b64_res.add_line(bformatstring % tuple(['-' * len(s) for s in bcolumnnames]))
                        for bst in b64_al_results:
                            b64_res.add_line(bst)

                        for btt in b64_al_tags:
                            st_value = patterns.ioc_match(btt, bogon_ip=True)
                            if len(st_value) > 0:
                                for ty, val in st_value.iteritems():
                                    if ty in self.tagtypes:
                                        if val == "":
                                            asc_asc = unicodedata.normalize('NFKC', val).encode('ascii', 'ignore')
                                            ascii_dict.setdefault(ty, set()).add(asc_asc)
                                            res.add_tag(TAG_TYPE[ty], asc_asc, TAG_WEIGHT.LOW)
                                        else:
                                            for v in val:
                                                ascii_dict.setdefault(ty, set()).add(v)
                                                res.add_tag(TAG_TYPE[ty], v, TAG_WEIGHT.LOW)

                # Store Unicode String Results
                if len(unicode_al_results) > 0:
                    unicode_dict = {}
                    for ust in unicode_al_results:
                        asc_ust = unicodedata.normalize('NFKC', ust).encode('ascii', 'ignore')
                        st_value = patterns.ioc_match(asc_ust, bogon_ip=True)
                        if len(st_value) > 0:
                            for ty, val in st_value.iteritems():
                                if ty in self.tagtypes:
                                    if val == "":
                                        unicode_dict.setdefault(ty, set()).add(asc_ust)
                                        res.add_tag(TAG_TYPE[ty], asc_ust, TAG_WEIGHT.LOW)
                                    else:
                                        for v in val:
                                            unicode_dict.setdefault(ty, set()).add(v)
                                            res.add_tag(TAG_TYPE[ty], v, TAG_WEIGHT.LOW)

                    if len(unicode_dict) > 0:
                        result_found = True
                        unicode_res = (ResultSection(SCORE.NULL, "FLARE FLOSS Unicode IOC Strings:",
                                                     body_format=TEXT_FORMAT.MEMORY_DUMP,
                                                     parent=res))
                        for k, l in sorted(unicode_dict.iteritems()):
                            for i in sorted(l):
                                unicode_res.add_line("Found %s string: %s" % (k.replace("_", " "), i))

                # Store Unicode Data:
                if unicode_found:
                    result_found = True
                    unicode_emb_res = (ResultSection(SCORE.NULL, "Found Unicode Embedded Strings in Non-Executable:",
                                                 body_format=TEXT_FORMAT.MEMORY_DUMP,
                                                 parent=res))
                    unicode_emb_res.add_line("Extracted over 50 bytes of possible embedded unicode from "
                                             "non-executable file. See extracted files.")

                # Store Encoded String Results
                if len(encoded_al_results) > 0:
                    result_found = True
                    encoded_res = (ResultSection(SCORE.NULL, "FLARE FLOSS Decoded Strings:",
                                                 body_format=TEXT_FORMAT.MEMORY_DUMP,
                                                 parent=res))
                    encoded_res.add_line(tabulate(encoded_al_results, headers=["Offset", "Called At", "String"]))
                    # Create AL tag for each unique decoded string
                    for st in encoded_al_tags:
                        res.add_tag(TAG_TYPE['FILE_DECODED_STRING'], st, TAG_WEIGHT.LOW)
                        # Create tags for strings matching indicators of interest
                        st_value = patterns.ioc_match(st, bogon_ip=True)
                        if len(st_value) > 0:
                            for ty, val in st_value.iteritems():
                                if ty in self.tagtypes:
                                    if val == "":
                                        res.add_tag(TAG_TYPE[ty], st, TAG_WEIGHT.LOW)
                                    else:
                                        for v in val:
                                            res.add_tag(TAG_TYPE[ty], v, TAG_WEIGHT.LOW)

                # Store Stacked String Results
                if len(stacked_al_results) > 0:
                    result_found = True
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
                            st_value = patterns.ioc_match(extract_st, bogon_ip=True)
                            if len(st_value) > 0:
                                for ty, val in st_value.iteritems():
                                    if ty in self.tagtypes:
                                        if val == "":
                                            res.add_tag(TAG_TYPE[ty], extract_st, TAG_WEIGHT.LOW)
                                        else:
                                            for v in val:
                                                res.add_tag(TAG_TYPE[ty], v, TAG_WEIGHT.LOW)

                # Store XOR embedded results
                # Result Graph:
                if len(xor_al_results) > 0:
                    x_res = (ResultSection(SCORE.NULL, "BBCrack XOR'd Strings:",
                                           body_format=TEXT_FORMAT.MEMORY_DUMP,
                                           parent=res))
                    result_found = True
                    xformatString = '%-20s %-7s %-7s %-50s'
                    xcolumnNames = ('Transform', 'Offset', 'Score', 'Decoded String')
                    x_res.add_line(xformatString % xcolumnNames)
                    x_res.add_line(xformatString % tuple(['-' * len(s) for s in xcolumnNames]))
                    for xst in xor_al_results:
                            x_res.add_line(xst)
                # Result Tags:
                for transform, regex, offset, score, smatch in xresult:
                    if regex in self.tagtypes:
                        res.add_tag(TAG_TYPE[regex], smatch, TAG_WEIGHT.LOW)
                        res.add_tag(TAG_TYPE[regex], smatch, TAG_WEIGHT.LOW)

                if result_found:
                    result.add_result(res)
