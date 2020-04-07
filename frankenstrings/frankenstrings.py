import binascii
import hashlib
import mmap
import os
import re

import magic
import pefile

from assemblyline.common.net import is_valid_domain, is_valid_email
from assemblyline_v4_service.common.balbuzard.bbcrack import bbcrack
from assemblyline_v4_service.common.balbuzard.patterns import PatternMatch
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.result import Result, ResultSection, BODY_FORMAT, Heuristic
from frankenstrings.flarefloss import strings
from frankenstrings.misc_tools.crowbar import CrowBar


def string_rep(b):
    """Helper method for returning bytes as a string literal without the b'' of string interpolation"""
    if type(b) is str:
        return b
    if type(b) is bytes:
        return repr(b)[2:-1]
    else:
        return


class FrankenStrings(ServiceBase):
    FILETYPES = [
        'application',
        'document',
        'exec',
        'image',
        'Microsoft',
        'text',
    ]

    HEXENC_STRINGS = [
        b'\\u',
        b'%u',
        b'\\x',
        b'0x',
        b'&H',  # hex notation in VBA
    ]

    def __init__(self, config=None):
        super(FrankenStrings, self).__init__(config)
        # Unless patterns are added/adjusted to patterns.py, the following should remain at 7:
        self.st_min_length = 7
        self.before = None
        self.sample_type = None

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
                    for ty, val in st_value.items():
                        if taglist and ty not in tags:
                            tags[ty] = set()
                        for v in val:
                            # For crowbar plugin
                            if savetoset:
                                self.before.add(v)
                            if ty == 'network.static.domain':
                                if not is_valid_domain(v.decode('utf-8')):
                                    continue
                            if ty == 'network.email.address':
                                if not is_valid_email(v.decode('utf-8')):
                                    continue
                            if len(v) < 1001:
                                res.add_tag(ty, v)
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
        decoded = b''

        if size == 2:
            while data != b'':
                decoded += binascii.a2b_hex(data[2:4])
                data = data[4:]
        if size == 4:
            while data != b'':
                decoded += binascii.a2b_hex(data[4:6]) + binascii.a2b_hex(data[2:4])
                data = data[6:]
        if size == 8:
            while data != b'':
                decoded += binascii.a2b_hex(data[8:10]) + binascii.a2b_hex(data[6:8]) + \
                           binascii.a2b_hex(data[4:6]) + binascii.a2b_hex(data[2:4])
                data = data[10:]
        if size == 16:
            while data != b'':
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
        newstr = b""

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

        qword = re.compile(rb'(?:'+re.escape(encoding)+b'[A-Fa-f0-9]{16})+')
        dword = re.compile(rb'(?:'+re.escape(encoding)+b'[A-Fa-f0-9]{8})+')
        word = re.compile(rb'(?:'+re.escape(encoding)+b'[A-Fa-f0-9]{4})+')
        by = re.compile(rb'(?:'+re.escape(encoding)+b'[A-Fa-f0-9]{2})+')

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
            uniq_char = set(decoded[0])
            if len(decoded[0]) >= 500:
                if len(uniq_char) > 20:
                    sha256hash = hashlib.sha256(decoded[0]).hexdigest()
                    shalist.append(sha256hash)
                    udata_file_name = f"{sha256hash[0:10]}_enchex_{encoding}_decoded"
                    udata_file_path = os.path.join(self.working_directory, udata_file_name)
                    with open(udata_file_path, 'wb') as unibu_file:
                        unibu_file.write(decoded[0])
                        self.log.debug(f"Submitted dropped file for analysis: {udata_file_path}")
                    request.add_extracted(udata_file_path, udata_file_name,
                                          "Extracted unicode file during FrankenStrings analysis")
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
                        if (ft in ftype and 'octet-stream' not in ftype) or ft in mag_ftype:
                            b64_file_name = f"{sha256hash[0:10]}_b64_decoded"
                            b64_file_path = os.path.join(self.working_directory, b64_file_name)
                            with open(b64_file_path, 'wb') as b64_file:
                                b64_file.write(base64data)
                                self.log.debug("Submitted dropped file for analysis: %s" % b64_file_path)
                            request.add_extracted(b64_file_path, b64_file_name,
                                                  "Extracted b64 file during FrankenStrings analysis")
                            results[sha256hash] = [len(b64_string), b64_string[0:50],
                                                   "[Possible file contents. See extracted files.]", ""]
                            return results

                # See if any IOCs in decoded data
                pat = self.ioc_to_tag(base64data, patterns, res, taglist=True)
                # Filter printable characters then put in results
                asc_b64 = bytes(i for i in base64data if 31 < i < 127)
                if len(asc_b64) > 0:
                    # If patterns exists, report. If not, report only if string looks interesting
                    if len(pat) > 0:
                        results[sha256hash] = [len(b64_string), b64_string[0:50], asc_b64, base64data]
                    # PDF and Office documents have too many FPS
                    elif not self.sample_type.startswith('document/office') \
                            and not self.sample_type.startswith('document/pdf'):
                        # If data has length greater than 50, and unique character to length ratio is high
                        uniq_char = set(asc_b64)
                        if len(uniq_char) > 12 and len(re.sub(b"[^A-Za-z0-9]+", b"", asc_b64)) > 50:
                            results[sha256hash] = [len(b64_string), b64_string[0:50], asc_b64, base64data]
                # If not all printable characters but IOCs discovered, extract to file
                elif len(pat) > 0:
                    b64_file_name = f"{sha256hash[0:10]}_b64_decoded"
                    b64_file_path = os.path.join(self.working_directory, b64_file_name)
                    with open(b64_file_path, 'wb') as b64_file:
                        b64_file.write(base64data)
                        self.log.debug(f"Submitted dropped file for analysis: {b64_file_path}")
                    request.add_extracted(b64_file_path, b64_file_name,
                                          "Extracted b64 file during FrankenStrings analysis")
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
        uniq_char = set(binstr)
        if len(uniq_char) < 7:
            return filefound, tags
        # If data is greater than 500 bytes create extracted file
        if len(binstr) > 500:
            if len(uniq_char) < 20:
                return filefound, tags
            filefound = True
            sha256hash = hashlib.sha256(binstr).hexdigest()
            ascihex_file_name = f"{sha256hash[0:10]}_asciihex_decoded"
            ascihex_file_path = os.path.join(self.working_directory, ascihex_file_name)
            with open(ascihex_file_path, 'wb') as fh:
                fh.write(binstr)
            request.add_extracted(ascihex_file_path, ascihex_file_name,
                                  "Extracted ascii-hex file during FrankenStrings analysis")
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
                        tags['file.string.blacklisted'] = {data: [match, transform]}
                    else:
                        tags[regex] = {data: [match, transform]}
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
                pe_file_name = f"{hashlib.sha256(pe_extract).hexdigest()[0:10]}_{fn}"
                pe_file_path = os.path.join(self.working_directory, pe_file_name)
                with open(pe_file_path, 'wb') as exe_file:
                    exe_file.write(pe_extract)
                    self.log.debug(f"Submitted dropped file for analysis: {pe_file_path}")
                request.add_extracted(pe_file_path, pe_file_name, msg)

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

# --- Execute ----------------------------------------------------------------------------------------------------------

    def execute(self, request):
        """ Main Module. See README for details."""
        result = Result()
        request.result = result
        patterns = PatternMatch()
        # For crowbar plugin
        self.before = set()
        self.sample_type = request.file_type
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
        else:
            max_size = self.config.get('max_size', 3000000)
            max_length = self.config.get('max_length', 5000)
            st_max_size = self.config.get('st_max_size', 0)
            bb_max_size = self.config.get('bb_max_size', 85000)

        # Begin analysis
        if (len(request.file_contents) or 0) >= max_size or self.sample_type.startswith("archive/"):
            # No analysis is done if the file is an archive or too large
            return

        # Generate section in results set
        b64_al_results = []
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
        res = (ResultSection("FrankenStrings Detected Strings of Interest:",
                             body_format=BODY_FORMAT.MEMORY_DUMP))

        file_data = request.file_contents

        # Find ASCII & Unicode IOC Strings
        # Find all patterns if the file is identified as code (for crowbar plugin)
        if self.sample_type.startswith('code'):
            chkl = False
            svse = True
        else:
            chkl = True
            svse = False

        file_plainstr_iocs = self.ioc_to_tag(file_data, patterns, res, taglist=True, check_length=chkl,
                                             strs_max_size=st_max_size, st_max_length=max_length, savetoset=svse)

        # Embedded executable -- all sample types
        # PE Strings
        pat_exedos = rb'(?s)This program cannot be run in DOS mode'
        pat_exeheader = rb'(?s)MZ.{32,1024}PE\000\000.+'

        for pos_exe in re.findall(pat_exeheader, file_data[1:]):
            if re.search(pat_exedos, pos_exe):
                pe_sha256 = hashlib.sha256(pos_exe).hexdigest()
                temp_file = os.path.join(self.working_directory, "EXE_TEMP_{}".format(pe_sha256))

                with open(temp_file, 'wb') as pedata:
                    pedata.write(pos_exe)

                embedded_pe = self.pe_dump(request, temp_file, offset=0, fn="embed_pe",
                                           msg="PE header strings discovered in sample",
                                           fail_on_except=True)

        # Possible encoded strings -- all sample types except code/* (code will be handled by crowbar plugin)
        # Find Base64 encoded strings and files of interest
        if not self.sample_type.startswith('code'):
            b64_matches = set()
            # Base64 characters with possible space, newline characters and HTML line feeds (&#(XA|10);)
            for b64_match in re.findall(b'([\x20]{0,2}(?:[A-Za-z0-9+/]{10,}={0,2}'
                                        b'(?:&#[x1][A0];){0,1}[\r]?[\n]?){2,})', file_data):
                b64_string = b64_match.replace(b'\n', b'').replace(b'\r', b'').replace(b' ', b'')\
                    .replace(b'&#xA;', b'').replace(b'&#10;', b'')
                if b64_string in b64_matches:
                    continue
                b64_matches.add(b64_string)
                uniq_char = set(b64_string)
                if len(uniq_char) > 6:
                    b64result = self.b64(request, b64_string, patterns, res)
                    if len(b64result) > 0:
                        b64_al_results.append(b64result)

            # UTF-16 strings
            for ust in strings.extract_unicode_strings(file_data, n=self.st_min_length):
                for b64_match in re.findall(b'([\x20]{0,2}(?:[A-Za-z0-9+/]{10,}={0,2}[\r]?[\n]?){2,})', ust.s):
                    b64_string = b64_match.replace(b'\n', b'').replace(b'\r', b'').replace(b' ', b'')
                    uniq_char = set(b64_string)
                    if len(uniq_char) > 6:
                        b64result = self.b64(request, b64_string, patterns, res)
                        if len(b64result) > 0:
                            b64_al_results.append(b64result)

            # Balbuzard's bbcrack XOR'd strings to find embedded patterns/PE files of interest
            if (len(request.file_contents) or 0) < bb_max_size:
                if request.deep_scan:
                    # BBcrack level 2 gives an error
                    #xresult = bbcrack(file_data, level=2)
                    xresult = bbcrack(file_data, level=1)
                else:
                    xresult = bbcrack(file_data, level=1)

                xindex = 0
                for transform, regex, offset, score, smatch in xresult:
                    if regex == 'EXE_HEAD':
                        xindex += 1
                        xtemp_file = os.path.join(self.working_directory, f"EXE_HEAD_{xindex}_{offset}_{score}.unXORD")
                        with open(xtemp_file, 'wb') as xdata:
                            xdata.write(smatch)
                        pe_extracted = self.pe_dump(request, xtemp_file, offset, fn="xorpe_decoded",
                                                    msg="Extracted xor file during FrakenStrings analysis.")
                        if pe_extracted:
                            xor_al_results.append('%-20s %-7s %-7s %-50s' % (str(transform), offset, score,
                                                                             "[PE Header Detected. "
                                                                             "See Extracted files]"))
                    else:
                        xor_al_results.append('%-20s %-7s %-7s %-50s'
                                              % (str(transform), offset, score, string_rep(smatch)))

        # Other possible encoded strings -- all sample types but code and executables
        if not self.sample_type.split('/', 1)[0] in ['executable', 'code']:
            # Unicode/Hex Strings
            for hes in self.HEXENC_STRINGS:
                hes_regex = re.compile(re.escape(hes) + b'[A-Fa-f0-9]{2}')
                if re.search(hes_regex, file_data) is not None:
                    uhash, unires = self.decode_encoded_udata(request, hes, file_data)
                    if len(uhash) > 0:
                        for usha in uhash:
                            unicode_al_dropped_results.append('{0}_{1}' .format(usha, hes))
                    if len(unires) > 0:
                        for i in unires:
                            unicode_al_results[i[0]] = [i[1], i[2], i[3]]

            # Go over again, looking for long ASCII-HEX character strings
            if not self.sample_type.startswith('document/office'):
                hex_pat = re.compile(b'((?:[0-9a-fA-F]{2}[\r]?[\n]?){16,})')
                for hex_match in re.findall(hex_pat, file_data):
                    hex_string = hex_match.replace(b'\r', b'').replace(b'\n', b'')
                    afile_found, asciihex_results = self.unhexlify_ascii(request, hex_string, request.file_type,
                                                                         patterns, res)
                    if afile_found:
                        asciihex_file_found = True
                    if asciihex_results != b"":
                        for ask, asi in asciihex_results.items():
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

        # Static decoding of code files
        if self.sample_type.startswith('code'):
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
                or len(unicode_al_results) > 0 or len(unicode_al_dropped_results) > 0 \
                or asciihex_file_found or len(asciihex_dict) > 0 or len(asciihex_bb_dict)\
                or cb_code_res:

            # Report ASCII String Results
            if len(file_plainstr_iocs) > 0:
                ascii_res = (ResultSection("FLARE FLOSS Plain IOC Strings:",
                                           body_format=BODY_FORMAT.MEMORY_DUMP,
                                           parent=res))
                for k, l in sorted(file_plainstr_iocs.items()):
                    for i in sorted(l):
                        ascii_res.add_line(f"Found {k.replace('_', ' ')} string: {string_rep(i)}")

            # Report B64 Results
            if len(b64_al_results) > 0:
                b64_ascii_content = []
                b64_res = (ResultSection("Base64 Strings:", heuristic=Heuristic(1), parent=res))
                b64index = 0
                for b64dict in b64_al_results:
                    for b64k, b64l in b64dict.items():
                        b64index += 1
                        sub_b64_res = (ResultSection(f"Result {b64index}", parent=b64_res))
                        sub_b64_res.add_line(f'BASE64 TEXT SIZE: {b64l[0]}')
                        sub_b64_res.add_line(f'BASE64 SAMPLE TEXT: {string_rep(b64l[1])}[........]')
                        sub_b64_res.add_line(f'DECODED SHA256: {b64k}')
                        subb_b64_res = (ResultSection("DECODED ASCII DUMP:",
                                                      body_format=BODY_FORMAT.MEMORY_DUMP, parent=sub_b64_res))
                        subb_b64_res.add_line(string_rep(b64l[2]))
                        if b64l[2] not in ["[Possible file contents. See extracted files.]",
                                           "[IOCs discovered with other non-printable data. See extracted files.]"]:
                            b64_ascii_content.append(b64l[2])
                # Write all non-extracted decoded b64 content to file
                if len(b64_ascii_content) > 0:
                    all_b64 = b"\n".join(b64_ascii_content)
                    b64_all_sha256 = hashlib.sha256(all_b64).hexdigest()
                    b64_file_path = os.path.join(self.working_directory, b64_all_sha256)
                    try:
                        with open(b64_file_path, 'wb') as fh:
                            fh.write(all_b64)
                        request.add_extracted(b64_file_path, f"all_b64_{b64_all_sha256[:7]}.txt",
                                              "all misc decoded b64 from sample")
                    except Exception as e:
                        self.log.error(f"Error while adding extracted b64 content: {b64_file_path}: {str(e)}")

            # Report XOR embedded results
            # Result Graph:
            if len(xor_al_results) > 0:
                x_res = (ResultSection("BBCrack XOR'd Strings:", body_format=BODY_FORMAT.MEMORY_DUMP,
                                       heuristic=Heuristic(2), parent=res))
                xformat_string = '%-20s %-7s %-7s %-50s'
                xcolumn_names = ('Transform', 'Offset', 'Score', 'Decoded String')
                x_res.add_line(xformat_string % xcolumn_names)
                x_res.add_line(xformat_string % tuple(['-' * len(s) for s in xcolumn_names]))
                for xst in xor_al_results:
                    x_res.add_line(xst)
            # Result Tags:
            for transform, regex, offset, score, smatch in xresult:
                if not regex.startswith("EXE_"):
                    res.add_tag(regex, smatch)
                    res.add_tag(regex, smatch)

            # Report Embedded PE
            if embedded_pe:
                res.add_subsection(ResultSection("Embedded PE header discovered in sample. "
                                                 "See extracted files.", heuristic=Heuristic(3)))

            # Report Unicode Encoded Data:
            if len(unicode_al_results) > 0 or len(unicode_al_dropped_results) > 0:
                unicode_emb_res = (ResultSection("Found Unicode-Like Strings in Non-Executable:",
                                                 body_format=BODY_FORMAT.MEMORY_DUMP,
                                                 parent=res))

                if len(unicode_al_results) > 0:
                    unires_index = 0
                    for uk, ui in unicode_al_results.items():
                        unires_index += 1
                        sub_uni_res = (ResultSection(f"Result {unires_index}", heuristic=Heuristic(4),
                                                     parent=unicode_emb_res))
                        sub_uni_res.add_line(f'ENCODED TEXT SIZE: {ui[0]}')
                        sub_uni_res.add_line(f'ENCODED SAMPLE TEXT: {string_rep(ui[1])}[........]')
                        sub_uni_res.add_line(f'DECODED SHA256: {uk}')
                        subb_uni_res = (ResultSection("DECODED ASCII DUMP:",
                                                      body_format=BODY_FORMAT.MEMORY_DUMP,
                                                      parent=sub_uni_res))
                        subb_uni_res.add_line('{}'.format(string_rep(ui[2])))
                        # Look for IOCs of interest
                        hits = self.ioc_to_tag(ui[2], patterns, res, st_max_length=1000, taglist=True)
                        if len(hits) > 0:
                            sub_uni_res.set_heuristic(6)
                            subb_uni_res.add_line("Suspicious string(s) found in decoded data.")
                        else:
                            sub_uni_res.set_heuristic(4)

                if len(unicode_al_dropped_results) > 0:
                    for ures in unicode_al_dropped_results:
                        uhas = ures.split('_')[0]
                        uenc = ures.split('_')[1]
                        unicode_emb_res.set_heuristic(5)
                        unicode_emb_res.add_line(f"Extracted over 50 bytes of possible embedded unicode with "
                                                 f"{uenc} encoding. SHA256: {uhas}. See extracted files.")
            # Report Ascii Hex Encoded Data:
            if asciihex_file_found:
                asciihex_emb_res = (ResultSection("Found Large Ascii Hex Strings in Non-Executable:",
                                                  body_format=BODY_FORMAT.MEMORY_DUMP,
                                                  heuristic=Heuristic(7),
                                                  parent=res))
                asciihex_emb_res.add_line("Extracted possible ascii-hex object(s). See extracted files.")

            if len(asciihex_dict) > 0:
                # Different scores are used depending on whether the file is a document
                heuristic = Heuristic(8)
                if request.file_type.startswith("document"):
                    heuristic = Heuristic(10)
                asciihex_res = (ResultSection("ASCII HEX DECODED IOC Strings:",
                                              body_format=BODY_FORMAT.MEMORY_DUMP,
                                              heuristic=heuristic,
                                              parent=res))
                for k, l in sorted(asciihex_dict.items()):
                    for i in l:
                        for ii in i:
                            asciihex_res.add_line(f"Found {k.replace('_', ' ')} decoded HEX string: {ii}")

            if len(asciihex_bb_dict) > 0:
                asciihex_res = (ResultSection("ASCII HEX AND XOR DECODED IOC Strings:",
                                              heuristic=Heuristic(9), parent=res))
                xindex = 0
                for k, l in sorted(asciihex_bb_dict.items()):
                    for i in l:
                        for kk, ii in i.items():
                            xindex += 1
                            asx_res = (ResultSection(f"Result {xindex}", parent=asciihex_res))
                            asx_res.add_line(f"Found {k.replace('_', ' ')} decoded HEX string, masked with "
                                             f"transform {ii[1]}:")
                            asx_res.add_line("Decoded XOR string:")
                            asx_res.add_line(ii[0])
                            asx_res.add_line("Original ASCII HEX String:")
                            asx_res.add_line(kk)
                            res.add_tag(k, ii[0])

            # Report Crowbar de-obfuscate results and add deob code to result
            if cb_code_res:
                res.add_subsection(cb_code_res)
                decodefn = f"{request.md5}_decoded"
                decodefp = os.path.join(self.working_directory, decodefn)
                with open(decodefp, 'wb') as dcf:
                    dcf.write(cb_decoded_data)
                    self.log.debug(f"Submitted dropped file for analysis: {decodefp}")
                request.add_extracted(decodefp, decodefn, "Debofuscated sample")
                for f in cb_filex:
                    request.add_extracted(f, os.path.basename(f),
                                          "Debofuscated file of interest extracted from sample")

            result.add_section(res)
