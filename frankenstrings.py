""" FrankenStrings Service
See README.md for details about this service.
"""
from assemblyline.al.service.base import ServiceBase
from assemblyline.al.common.result import Result, ResultSection, SCORE, TAG_TYPE, TAG_WEIGHT, TEXT_FORMAT
from collections import namedtuple
import binascii
import hashlib
import magic
import mmap
import os
import string
import re

pefile = None
bbcrack = None
PatternMatch = None


# noinspection PyCallingNonCallable
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

    # noinspection PyUnresolvedReferences
    def import_service_deps(self):
        global pefile, bbcrack, PatternMatch
        import pefile
        from al_services.alsvc_frankenstrings.balbuzard.bbcrack import bbcrack
        from al_services.alsvc_frankenstrings.balbuzard.patterns import PatternMatch

    def __init__(self, cfg=None):
        super(FrankenStrings, self).__init__(cfg)
        self.filetypes = ['application',
                          'exec',
                          'image',
                          'text',
                          ]
        self.shcode_strings = ['00000000000000000000000000000000',  # null bytes
                               '9090',  # nop nop
                               '31c0',  # xor eax eax
                               '31C0',
                               '33c0',
                               '33C0',
                               '31db',  # xor ebx ebx
                               '31DB',
                               '33db',
                               '33DB',
                               '31d2',  # xor edx edx
                               '31D2',
                               '33d2',
                               '33D2',
                               '31c9',  # xor ecx ecx
                               '31C9',
                               '33c9',
                               '33C9',
                               '64a130000000',  # mov eax, fs:0x30
                               '64A130000000',
                               ]

    def start(self):
        self.log.debug("FrankenStrings service started")

# --- Support Functions ------------------------------------------------------------------------------------------------

    # CIC: Call If Callable
    @staticmethod
    def cic(expression):
        """
        From 'base64dump.py' by Didier Stevens@https://DidierStevens.com
        """
        if callable(expression):
            return expression()
        else:
            return expression

    # IFF: IF Function
    @classmethod
    def iff(cls, expression, value_true, value_false):
        """
        From 'base64dump.py' by Didier Stevens@https://DidierStevens.com
        """
        if expression:
            return cls.cic(value_true)
        else:
            return cls.cic(value_false)

    # Ascii Dump
    @classmethod
    def ascii_dump(cls, data):
        return ''.join([cls.iff(ord(b) >= 32, b, '.') for b in data])

    @staticmethod
    def decode_bu(data, size):
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

        # Test if all match size of longest string (if by chance the data was separated by a character --i.e. ','--).
        # if true, combine all data and return string,
        # else return longest string if greater than 50 bytes,
        # else return empty string

        if all(len(i) == maxstr for i in lisdata):
            for i in lisdata:
                newstr += i
            return newstr
        elif maxstr > 50:
            return max(lisdata, key=len)
        else:
            return newstr

    @classmethod
    def decode_encoded_udata(cls, encoding, data):
        """
        Adjusted code in base64decode.py to take in to account byte, word, dword, qword
        """
        decoded_list = []
        decoded = ''

        qword = re.compile(r'\(?:' + re.escape(encoding) + r'[A-Fa-f0-9]{16}\)+\)')
        dword = re.compile(r'\(?:' + re.escape(encoding) + r'[A-Fa-f0-9]{8}\)+\)')
        word = re.compile(r'\(?:' + re.escape(encoding) + r'[A-Fa-f0-9]{4}\)+\)')
        by = re.compile(r'\(?:' + re.escape(encoding) + r'[A-Fa-f0-9]{2}\)+\)')

        qbu = re.findall(qword, data)
        if len(qbu) > 0:
            qlstr = cls.unicode_longest_string(qbu)
            if len(qlstr) > 50:
                decoded_list.append(cls.decode_bu(qlstr, size=16))
        dbu = re.findall(dword, data)
        if len(dbu) > 0:
            dlstr = cls.unicode_longest_string(dbu)
            if len(dlstr) > 50:
                decoded_list.append(cls.decode_bu(dlstr, size=8))
        wbu = re.findall(word, data)
        if len(wbu) > 0:
            wlstr = cls.unicode_longest_string(wbu)
            if len(wlstr) > 50:
                decoded_list.append(cls.decode_bu(wlstr, size=4))
        bbu = re.findall(by, data)
        if len(bbu) > 0:
            blstr = cls.unicode_longest_string(bbu)
            if len(blstr) > 50:
                decoded_list.append(cls.decode_bu(blstr, size=2))

        if len(decoded_list) > 0:
            decoded = max(decoded_list, key=len)

        return decoded

    # Base64 Parse
    # noinspection PyBroadException
    def b64(self, request, b64_string):
        """
        Using some selected code from 'base64dump.py' by Didier Stevens@https://DidierStevens.com
        """
        results = 0
        tag = 0
        if len(b64_string) >= 16 and len(b64_string) % 4 == 0:
            try:
                base64data = binascii.a2b_base64(b64_string)
                # Search for embedded files of interest
                if 1500 < len(base64data) < 8000000:
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
                            return results, tag
                if all(ord(c) < 128 for c in base64data):
                    asc_b64 = self.ascii_dump(base64data)
                    results = ('%-7d %-50s %-60s %-32s' % (len(b64_string), b64_string[0:50],
                                                           asc_b64[0:60],
                                                           hashlib.md5(base64data).hexdigest()))
                    tag = asc_b64
            except:
                return results, tag
        return results, tag

    # noinspection PyBroadException
    def unhexlify_shellcode(self, request, data):
        """
        Plain ascii hex conversion.
        '"""
        try:
            matchbuf = ""
            for match in re.findall('[0-9a-fA-F]{128,}', data):
                matchbuf += match
            if len(matchbuf) > 0:
                if len(matchbuf) % 2 != 0:
                    matchbuf = matchbuf[:-1]
                binstr = binascii.unhexlify(matchbuf)
                ascihex_file_path = os.path.join(self.working_directory, "{}_asciihex_decoded"
                                                 .format(hashlib.md5(binstr).hexdigest()))
                with open(ascihex_file_path, 'wb') as fh:
                    fh.write(binstr)
                request.add_extracted(ascihex_file_path, "Extracted ascii-hex file during FrankenStrings analysis.")
        except:
            return
        return

    def unhexlify_rtf(self, request, data):
        """
        RTF objdata ascii hex extract. Inspired by Talos blog post "How Malformed RTF Defeats Security Engines", and
        help from information in http://www.decalage.info/rtf_tricks. This is a backup to the oletools service.
        Will need more work.
        """
        try:
            # Get objdata
            while data.find("{\*\objdata") != -1:

                obj = data.find("{\*\objdata")
                data = data[obj:]

                d = ""
                bcount = -1
                # Walk the objdata item and extract until 'real' closing brace reached.
                while bcount != 0:
                    if len(data) == 0:
                        # Did not find 'real' closing brace
                        return
                    else:
                        c = data[0]
                        if c == '{':
                            if bcount != -1:
                                bcount += 1
                            else:
                                bcount = 1
                            bcount += 1
                        if c == '}':
                            bcount -= 1
                        d += c
                        data = data[1:]

                # Transform the data to remove any potential obfuscation:
                # 1. Attempt to find (what appears to be a common) OLESAVETOSTREAM serial string and remove all
                # characters up to doc header if found. This section will need to be improved later.
                olesavetostream = re.compile(r"^[{]\\\*\\objdata.{0,2000}"
                                             r"0[\s]*1[\s]*0[\s]*5[\s]*0[\s]*0[\s]*0[\s]*0[\s]*"
                                             r"0[\s]*2[\s]*0[\s]*0[\s]*0[\s]*0",
                                             re.DOTALL)
                if re.search(olesavetostream, d):
                    docstart = d[:2011].upper().find("D0CF11E0")
                    if docstart != -1:
                        d = d[docstart:]
                # 2. Transform any embedded binary data
                if d.find("\\bin") != -1:
                    binreg = re.compile(r"\\bin[0]{0,250}[1-9]{0,4}")
                    for b in re.findall(binreg, d):
                        blen = re.sub("[a-z0]{0,4}", "", b[-4:])
                        rstr = re.escape(b)+"[\s]*"+".{"+blen+"}"
                        d = re.sub(rstr, str(rstr[-int(blen):].encode('hex')), d)
                # 3. Remove remaining control words
                d = re.sub(r"\\[A-Za-z0-9][\s]*", "", d)
                # 4. Remove any other characters that are not ascii hex
                d = re.sub("[ -/:-@\[-`{-~g-zG-Z\s\x00]", "", ''.join([x for x in d if ord(x) < 128]))

                # Convert the ascii hex and extract file
                if len(d) > 0:
                    if len(d) % 2 != 0:
                        d = d[:-1]
                    bstr = binascii.unhexlify(d)
                    ascihex_path = os.path.join(self.working_directory, "{}_rtfobj_hex_decoded"
                                                .format(hashlib.md5(bstr).hexdigest()))
                    with open(ascihex_path, 'wb') as fh:
                        fh.write(bstr)
                    request.add_extracted(ascihex_path, "Extracted rtf objdata ascii hex file during "
                                                        "FrankenStrings analysis.")

        except:
            pass

        return

    # Executable extraction
    # noinspection PyBroadException
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
                pe_extract = pedata
        except:
            pe_extract = pedata

        xpe_file_path = os.path.join(self.working_directory, "{}_xorpe_decoded"
                                     .format(hashlib.md5(pe_extract).hexdigest()))
        request.add_extracted(xpe_file_path, "Extracted xor file during FrakenStrings analysis.")
        with open(xpe_file_path, 'wb') as exe_file:
            exe_file.write(pe_extract)
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
        for fva, _ in decoding_functions_candidates:
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

        # Filters for submission modes. Change at will! (Listed in order of use)
        if request.deep_scan:
            # Maximum size of submitted file to run this service:
            max_size = 8000000
            # String length minimum
            # Used in basic ASCII and UNICODE modules. Also the filter size for any code that sends strings
            # to patterns.py
            # Unless patterns are added/adjusted to patterns.py, the following should remain at 7:
            st_min_length = 7
            # String length maximum
            # Used in basic ASCII and UNICODE modules:
            st_max_length = 1000000
            # String list maximum size
            # List produced by basic ASCII and UNICODE module results and will determine
            # if patterns.py will only evaluate network IOC patterns:
            strs_max_size = 1000000
            # BBcrack maximum size of submitted file to run module:
            bb_max_size = 3000000
            # Flare Floss  maximum size of submitted file to run encoded/stacked string modules:
            ff_max_size = 3000000
            # Flare Floss minimum string size for encoded/stacked string modules:
            ff_enc_min_length = 6
            ff_stack_min_length = 6
        else:
            max_size = 3000000
            st_min_length = 7
            st_max_length = 500
            # Default 0, meaning by default only network IOC patterns are matched:
            strs_max_size = 0
            bb_max_size = 500000
            ff_max_size = 200000
            ff_enc_min_length = 6
            ff_stack_min_length = 6

        # Begin analysis

        if (request.task.size or 0) < max_size and not request.tag.startswith("archive/"):
            # Generate section in results set
            from floss import decoding_manager
            from floss import identification_manager as im, strings, stackstrings
            from fuzzywuzzy import process
            from tabulate import tabulate
            import viv_utils
            import unicodedata

            ascii_dict = {}
            b64_al_results = []
            b64_al_tags = set()
            encoded_al_results = []
            encoded_al_tags = set()
            stacked_al_results = []
            unicode_dict = {}
            xor_al_results = []

            unicode_found = False

# --- Generate Results -------------------------------------------------------------------------------------------------
            patterns = PatternMatch()
            # Static strings -- all file types

            alfile = request.download()
            with open(alfile, "rb") as f:
                orig_submitted_file = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
                file_data = f.read()

            # FLOSS ascii string extract
            astrings = set()
            for s in strings.extract_ascii_strings(orig_submitted_file, n=st_min_length):
                if len(s.s) < st_max_length:
                    astrings.add(s.s)

            # FLOSS unicode string extract
            ustrings = set()
            for s in strings.extract_unicode_strings(orig_submitted_file, n=st_min_length):
                if len(s.s) < st_max_length:
                    ustrings.add(s.s)

            orig_submitted_file.close()

            # Examine ascii
            if len(astrings) > strs_max_size:
                jn = True
            else:
                jn = False

            for s in astrings:
                st_value = patterns.ioc_match(s, bogon_ip=True, just_network=jn)
                if len(st_value) > 0:
                    for ty, val in st_value.iteritems():
                        if val == "":
                            asc_asc = unicodedata.normalize('NFKC', val).encode('ascii', 'ignore')
                            ascii_dict.setdefault(ty, set()).add(asc_asc)
                        else:
                            for v in val:
                                ascii_dict.setdefault(ty, set()).add(v)

            # Examine unicode
            if len(ustrings) > strs_max_size:
                jn = True
            else:
                jn = False

            for s in ustrings:
                st_value = patterns.ioc_match(s, bogon_ip=True, just_network=jn)
                if len(st_value) > 0:
                    for ty, val in st_value.iteritems():
                        if val == "":
                            asc_asc = unicodedata.normalize('NFKC', val).encode('ascii', 'ignore')
                            unicode_dict.setdefault(ty, set()).add(asc_asc)
                        else:
                            for v in val:
                                unicode_dict.setdefault(ty, set()).add(v)

            # Find Base64 ASCII and files of interest
            for b64_tuple in re.findall('(([\x20]{0,2}[A-Za-z0-9+/]{3,}={0,2}[\r]?[\n]?){6,})', file_data):
                b64_string = b64_tuple[0].replace('\n', '').replace('\r', '').replace(' ', '')
                uniq_char = ''.join(set(b64_string))
                if len(uniq_char) > 6:
                    b64result, b64tag = self.b64(request, b64_string)
                    if b64result != 0:
                        b64_al_results.append(b64result)
                    if b64tag != 0:
                        b64_al_tags.add(b64tag)

            # Balbuzard's bbcrack XOR'd strings to find embedded patterns/PE files of interest
            xresult = []
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
                        xdata = open(xtemp_file, 'wb')
                        xdata.write(smatch)
                        xdata.close()
                        self.pe_dump(request, xtemp_file, offset)
                        xor_al_results.append('%-20s %-7s %-7s %-50s' % (str(transform), offset, score,
                                                                         "[PE Header Detected. See Extracted files]"))
                    else:
                        xor_al_results.append('%-20s %-7s %-7s %-50s' % (str(transform), offset, score, smatch))

            # Unicode/Hex Strings -- Non-executable files
            if not request.tag.startswith("executable/"):
                # base64dump.py unicode extract
                if re.search(r'\\u[A-Fa-f0-9]{2}', file_data) is not None:
                    bu_uni_decoded = self.decode_encoded_udata(file_data, '\\u')
                    if bu_uni_decoded != '':
                        unicode_found = True
                        unibu_file_path = os.path.join(self.working_directory, "{}_unibu_decoded"
                                                       .format(hashlib.md5(bu_uni_decoded).hexdigest()))
                        request.add_extracted(unibu_file_path,
                                              "Extracted \u_unicode file during FrankenStrings analysis.")
                        with open(unibu_file_path, 'wb') as unibu_file:
                            unibu_file.write(bu_uni_decoded)
                            self.log.debug("Submitted dropped file for analysis: %s" % unibu_file_path)

                if re.search(r'%u[A-Fa-f0-9]{2}', file_data) is not None:
                    pu_uni_decoded = self.decode_encoded_udata(file_data, '%u')
                    if pu_uni_decoded != '':
                        unicode_found = True
                        unipu_file_path = os.path.join(self.working_directory, "{}_unipu_decoded"
                                                       .format(hashlib.md5(pu_uni_decoded).hexdigest()))
                        request.add_extracted(unipu_file_path,
                                              "Extracted %u_unicode file during FrankenStrings analysis.")
                        with open(unipu_file_path, 'wb') as unipu_file:
                            unipu_file.write(pu_uni_decoded)
                            self.log.debug("Submitted dropped file for analysis: %s" % unipu_file_path)

                if re.search(r'0x[A-Fa-f0-9]{2}', file_data) is not None:
                    x_uni_decoded = self.decode_encoded_udata(file_data, '0x')
                    if x_uni_decoded != '':
                        unicode_found = True
                        unix_file_path = os.path.join(self.working_directory,
                                                      "{}_uni0x_decoded".format(hashlib.md5(x_uni_decoded).hexdigest()))
                        request.add_extracted(unix_file_path,
                                              "Extracted 0x_unicode file during FrankenStrings analysis.")
                        with open(unix_file_path, 'wb') as unix_file:
                            unix_file.write(x_uni_decoded)
                            self.log.debug("Submitted dropped file for analysis: %s" % unix_file_path)

                if re.search(r'\\x[A-Fa-f0-9]{2}', file_data) is not None:
                    fx_uni_decoded = self.decode_encoded_udata(file_data, '\\x')
                    if fx_uni_decoded != '':
                        unicode_found = True
                        unifx_file_path = os.path.join(self.working_directory, "{}_uni2fx_decoded"
                                                       .format(hashlib.md5(fx_uni_decoded).hexdigest()))
                        request.add_extracted(unifx_file_path,
                                              "Extracted /x_unicode file during FrankenStrings analysis.")
                        with open(unifx_file_path, 'wb') as unifx_file:
                            unifx_file.write(fx_uni_decoded)
                            self.log.debug("Submitted dropped file for analysis: %s" % unifx_file_path)

                # Look for hex-string matches from list and run extraction module if any found
                if (request.task.size or 0) < 100000:
                    self.unhexlify_shellcode(request, file_data)
                else:
                    for shstr in self.shcode_strings:
                        if file_data.find(shstr) != -1:
                            self.unhexlify_shellcode(request, file_data)
                            break

                # RTF object data hex
                if file_data.find("{\*\objdata") != -1:
                    self.unhexlify_rtf(request, file_data)

            # Encoded/Stacked strings -- Windows executable file types
            if (request.task.size or 0) < ff_max_size:

                m = magic.Magic()
                file_magic = m.from_buffer(file_data)

                if request.tag.startswith("executable/windows/") and not file_magic.endswith("compressed"):

                    try:
                        vw = viv_utils.getWorkspace(alfile, should_save=False)
                    except Exception, e:
                        vw = False
                        self.log.exception('VIV Utils getWorkspace failed: {0}' .format(e.message))

                    if vw:
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

# --- Store Results ----------------------------------------------------------------------------------------------------

            if len(ascii_dict) > 0 \
                    or len(unicode_dict) > 0 \
                    or len(b64_al_results) > 0 \
                    or len(xor_al_results) > 0 \
                    or len(encoded_al_results) > 0 \
                    or len(stacked_al_results) > 0 \
                    or unicode_found:

                res = (ResultSection(SCORE.LOW, "FrankenStrings Detected Strings of Interest:",
                                     body_format=TEXT_FORMAT.MEMORY_DUMP))
                patterns = PatternMatch()

                # Store ASCII String Results
                if len(ascii_dict) > 0:
                    ascii_res = (ResultSection(SCORE.NULL, "FLARE FLOSS ASCII IOC Strings:",
                                               body_format=TEXT_FORMAT.MEMORY_DUMP,
                                               parent=res))
                    for k, l in sorted(ascii_dict.iteritems()):
                        for i in sorted(l):
                            ascii_res.add_line("Found %s string: %s" % (k.replace("_", " "), i))
                            res.add_tag(TAG_TYPE[k], i, TAG_WEIGHT.LOW)

                # Store Unicode String Results
                if len(unicode_dict) > 0:
                    unicode_res = (ResultSection(SCORE.NULL, "FLARE FLOSS Unicode IOC Strings:",
                                                 body_format=TEXT_FORMAT.MEMORY_DUMP,
                                                 parent=res))
                    for k, l in sorted(unicode_dict.iteritems()):
                        for i in sorted(l):
                            unicode_res.add_line("Found %s string: %s" % (k.replace("_", " "), i))
                            res.add_tag(TAG_TYPE[k], i, TAG_WEIGHT.LOW)

                # Store B64 Results
                if len(b64_al_results) > 0:
                    b64_res = (ResultSection(SCORE.NULL, "Base64 Strings:",
                                             body_format=TEXT_FORMAT.MEMORY_DUMP,
                                             parent=res))
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
                                if val == "":
                                    asc_asc = unicodedata.normalize('NFKC', val).encode('ascii',
                                                                                        'ignore')
                                    ascii_dict.setdefault(ty, set()).add(asc_asc)
                                    res.add_tag(TAG_TYPE[ty], asc_asc, TAG_WEIGHT.LOW)
                                else:
                                    for v in val:
                                        ascii_dict.setdefault(ty, set()).add(v)
                                        res.add_tag(TAG_TYPE[ty], v, TAG_WEIGHT.LOW)

                # Store XOR embedded results
                # Result Graph:
                if len(xor_al_results) > 0:
                    x_res = (ResultSection(SCORE.NULL, "BBCrack XOR'd Strings:",
                                           body_format=TEXT_FORMAT.MEMORY_DUMP,
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

                # Store Unicode Encoded Data:
                if unicode_found:
                    unicode_emb_res = (ResultSection(SCORE.NULL, "Found Unicode Embedded Strings in Non-Executable:",
                                                     body_format=TEXT_FORMAT.MEMORY_DUMP,
                                                     parent=res))
                    unicode_emb_res.add_line("Extracted over 50 bytes of possible embedded unicode from "
                                             "non-executable file. See extracted files.")

                # Store Encoded String Results
                if len(encoded_al_results) > 0:
                    encoded_res = (ResultSection(SCORE.NULL, "FLARE FLOSS Decoded Strings:",
                                                 body_format=TEXT_FORMAT.MEMORY_DUMP,
                                                 parent=res))
                    encoded_res.add_line(tabulate(encoded_al_results, headers=["Offset", "Called At", "String"]))
                    # Create AL tag for each unique decoded string
                    for st in encoded_al_tags:
                        res.add_tag(TAG_TYPE['FILE_DECODED_STRING'], st, TAG_WEIGHT.LOW)
                        # Create tags for strings matching indicators of interest
                        if len(st) > st_min_length:
                            st_value = patterns.ioc_match(st, bogon_ip=True)
                            if len(st_value) > 0:
                                for ty, val in st_value.iteritems():
                                    if val == "":
                                        res.add_tag(TAG_TYPE[ty], st, TAG_WEIGHT.LOW)
                                    else:
                                        for v in val:
                                            res.add_tag(TAG_TYPE[ty], v, TAG_WEIGHT.LOW)

                # Store Stacked String Results
                if len(stacked_al_results) > 0:
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
                            if len(extract_st) > st_min_length:
                                st_value = patterns.ioc_match(extract_st, bogon_ip=True)
                                if len(st_value) > 0:
                                    for ty, val in st_value.iteritems():
                                        if val == "":
                                            res.add_tag(TAG_TYPE[ty], extract_st, TAG_WEIGHT.LOW)
                                        else:
                                            for v in val:
                                                res.add_tag(TAG_TYPE[ty], v, TAG_WEIGHT.LOW)

                result.add_result(res)
