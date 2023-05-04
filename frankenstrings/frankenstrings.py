""" FrankenStrings Service """

import binascii
import hashlib
import mmap
import os
import re
import traceback

from typing import Dict, Iterable, List, Optional, Set, Tuple

import magic
import pefile

from multidecoder.multidecoder import Multidecoder
from multidecoder.json_conversion import tree_to_json

from assemblyline.common.net import is_valid_domain, is_valid_email
from assemblyline.common.str_utils import safe_str
from assemblyline_v4_service.common.balbuzard.bbcrack import bbcrack
from assemblyline_v4_service.common.balbuzard.patterns import PatternMatch
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.result import Result, ResultSection, BODY_FORMAT, Heuristic
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.task import MaxExtractedExceeded

from frankenstrings.flarefloss import strings

# Type aliases
Tags = Dict[str, Set[str]]
B64Result = Dict[str, Tuple[int, bytes, bytes, bytes]]

# PE Strings
PAT_EXEDOS = rb"(?s)This program cannot be run in DOS mode"
PAT_EXEHEADER = rb"(?s)MZ.{32,1024}PE\000\000.+"

BASE64_RE = rb"(?:[A-Za-z0-9+/]{10,}(?:&#(?:xA|10);)?[\r]?[\n]?){2,}[A-Za-z0-9+/]{2,}={0,2}"


def truncate(text: str, length: int = 500):
    if len(text) <= length:
        return text
    return text[:length] + "[...]"


class FrankenStrings(ServiceBase):
    """FrankenStrings Service"""

    FILETYPES = [
        "application",
        "document",
        "exec",
        "image",
        "Microsoft",
        "text",
    ]

    HEXENC_STRINGS = [
        b"\\u",
        b"%u",
        b"\\x",
        b"0x",
        b"&H",  # hex notation in VBA
    ]

    BBCRACK_TO_TAG = {
        "NET_FULL_URI": "network.static.uri",
    }

    def __init__(self, config: Optional[Dict] = None) -> None:
        super().__init__(config)
        # Unless patterns are added/adjusted to patterns.py, the following should remain at 7:
        self.st_min_length = 7
        self.sample_type = ""
        self.excess_extracted = 0

    # --- Support Functions --------------------------------------------------------------------------------------------

    def extract_file(self, request, data, file_name, description):
        """Adds data to a request as an extracted file

        request: the request
        data: the file data
        filename: the name to give the file
        description: the desctiption of the file to give the request
        """
        if self.excess_extracted:
            # Already over maximimum number of extracted files
            self.excess_extracted += 1
            return
        try:
            # If for some reason the directory doesn't exist, create it
            if not os.path.exists(self.working_directory):
                os.makedirs(self.working_directory)
            file_path = os.path.join(self.working_directory, file_name)
            with open(file_path, "wb") as f:
                f.write(data)
            request.add_extracted(file_path, file_name, description, safelist_interface=self.api_interface)
        except MaxExtractedExceeded:
            self.excess_extracted += 1
        except Exception:
            self.log.error(f"Error extracting {file_name} from {request.sha256}: {traceback.format_exc(limit=2)}")

    def ioc_to_tag(
        self,
        data: bytes,
        patterns: PatternMatch,
        res: Optional[ResultSection] = None,
        taglist: bool = False,
        check_length: bool = False,
        strs_max_size: int = 0,
        st_max_length: int = 300,
    ) -> Tags:
        """Searches data for patterns and adds as AL tag to result output.

        Args:
            data: Data to be searched.
            patterns: FrankenStrings Patterns() object.
            res: AL result.
            taglist: True if tag list should be returned.
            check_length: True if length of string should be compared to st_max_length.
            strs_max_size: Maximum size of strings list. If greater then only network IOCs will be searched.
            st_max_length: Maximum length of a string from data that can be searched.

        Returns: tag list as dictionary (always empty if taglist is false)
        """

        tags: Tags = {}

        min_length = self.st_min_length if check_length else 4

        strs: Set[bytes] = set()
        just_network = False

        # Flare-FLOSS ascii string extract
        for ast in strings.extract_ascii_strings(data, n=min_length):
            if not check_length or len(ast.s) < st_max_length:
                strs.add(ast.s)
        # Flare-FLOSS unicode string extract
        for ust in strings.extract_unicode_strings(data, n=min_length):
            if not check_length or len(ust.s) < st_max_length:
                strs.add(ust.s)

        if check_length and len(strs) > strs_max_size:
            just_network = True

        for s in strs:
            st_value: Dict[str, Iterable[bytes]] = patterns.ioc_match(s, bogon_ip=True, just_network=just_network)
            for ty, val in st_value.items():
                if taglist and ty not in tags:
                    tags[ty] = set()
                for v in val:
                    if ty == "network.static.domain" and not is_valid_domain(v.decode("utf-8")):
                        continue
                    if ty == "network.email.address" and not is_valid_email(v.decode("utf-8")):
                        continue
                    if len(v) < 1001:
                        if res:
                            res.add_tag(ty, safe_str(v))
                        if taglist:
                            tags[ty].add(safe_str(v))
        return tags

    @staticmethod
    def decode_bu(data: bytes, size: int) -> bytes:
        """Convert ascii to hex.

        Args:
            data: Ascii string to be converted.
            size: Unit size.

        Returns:
            Decoded data.
        """
        decoded = b""

        if size == 2:
            while data != b"":
                decoded += binascii.a2b_hex(data[2:4])
                data = data[4:]
        if size == 4:
            while data != b"":
                decoded += binascii.a2b_hex(data[4:6]) + binascii.a2b_hex(data[2:4])
                data = data[6:]
        if size == 8:
            while data != b"":
                decoded += (
                    binascii.a2b_hex(data[8:10])
                    + binascii.a2b_hex(data[6:8])
                    + binascii.a2b_hex(data[4:6])
                    + binascii.a2b_hex(data[2:4])
                )
                data = data[10:]
        if size == 16:
            while data != b"":
                decoded += (
                    binascii.a2b_hex(data[16:18])
                    + binascii.a2b_hex(data[14:16])
                    + binascii.a2b_hex(data[12:14])
                    + binascii.a2b_hex(data[10:12])
                    + binascii.a2b_hex(data[8:10])
                    + binascii.a2b_hex(data[6:8])
                    + binascii.a2b_hex(data[4:6])
                    + binascii.a2b_hex(data[2:4])
                )
                data = data[18:]

        return decoded

    @staticmethod
    def unicode_longest_string(listdata: List[bytes]) -> bytes:
        """Compare sizes of unicode strings.

        Args:
            listdata: A list of binary strings

        Returns:
            Result of test: Do all strings match in length?
                If True, returns all strings combined.
                If False, returns longest string greater than 50 bytes.
                If no string longer than 50 bytes, returns empty string.
        """
        maxstr = max(listdata, key=len)
        newstr = b""

        if all(len(i) == len(maxstr) for i in listdata):
            for i in listdata:
                newstr += i
            return newstr
        if len(maxstr) > 50:
            return maxstr
        return newstr

    def decode_encoded_udata(
        self, request: ServiceRequest, encoding: bytes, data: bytes, decoded_res: Dict[str, Tuple[bytes, bytes]]
    ) -> List[str]:
        """Compare sizes of unicode strings. Some code taken from bas64dump.py @ https://DidierStevens.com.

        Args:
            request: AL request object (for submitting extracted files to AL when needed).
            encoding: Encoding string used (i.e. '0x').
            data: Data to be examined.

        Returns:
            List of hashes of extracted files submitted to AL and list of decoded unicode data information.
        """

        decoded_list: List[Tuple[bytes, bytes]] = []
        dropped: List[str] = []

        qword = re.compile(rb"(?:" + re.escape(encoding) + b"[A-Fa-f0-9]{16})+")
        dword = re.compile(rb"(?:" + re.escape(encoding) + b"[A-Fa-f0-9]{8})+")
        word = re.compile(rb"(?:" + re.escape(encoding) + b"[A-Fa-f0-9]{4})+")
        byte = re.compile(rb"(?:" + re.escape(encoding) + b"[A-Fa-f0-9]{2})+")

        qbu = re.findall(qword, data)
        if qbu:
            qlstr = self.unicode_longest_string(qbu)
            if len(qlstr) > 50:
                decoded_list.append((self.decode_bu(qlstr, size=16), qlstr[:200]))
        dbu = re.findall(dword, data)
        if dbu:
            dlstr = self.unicode_longest_string(dbu)
            if len(dlstr) > 50:
                decoded_list.append((self.decode_bu(dlstr, size=8), dlstr[:200]))
        wbu = re.findall(word, data)
        if wbu:
            wlstr = self.unicode_longest_string(wbu)
            if len(wlstr) > 50:
                decoded_list.append((self.decode_bu(wlstr, size=4), wlstr[:200]))
        bbu = re.findall(byte, data)
        if bbu:
            blstr = self.unicode_longest_string(bbu)
            if len(blstr) > 50:
                decoded_list.append((self.decode_bu(blstr, size=2), blstr[:200]))

        filtered_list = filter(lambda x: len(x[0]) > 30, decoded_list)

        for decoded in filtered_list:
            uniq_char = set(decoded[0])
            sha256hash = hashlib.sha256(decoded[0]).hexdigest()
            if len(decoded[0]) >= 500:
                if len(uniq_char) > 20:
                    dropped.append(sha256hash)
                    udata_file_name = f"{sha256hash[0:10]}_enchex_{safe_str(encoding)}_decoded"
                    self.extract_file(
                        request, decoded[0], udata_file_name, "Extracted unicode file during FrankenStrings analysis"
                    )
            elif len(uniq_char) > 6:
                decoded_res[sha256hash] = decoded

        return dropped

    # Base64 Parse
    def b64(self, request: ServiceRequest, b64_string: bytes, patterns: PatternMatch) -> Tuple[B64Result, Tags]:
        """Decode B64 data.

        Args:
            request: AL request object (for submitting extracted files to AL when needed).
            b64_string: Possible base64 string.
            patterns: FrankenStrings patterns object.

        Returns:
            Result information.
        """
        results: B64Result = {}
        pat: Tags = {}
        if len(b64_string) >= 16 and len(b64_string) % 4 == 0:
            # noinspection PyBroadException
            try:
                base64data = binascii.a2b_base64(b64_string)
                sha256hash = hashlib.sha256(base64data).hexdigest()
                # Search for embedded files of interest
                if 200 < len(base64data) < 10000000:
                    m = magic.Magic(mime=True)
                    mag = magic.Magic()
                    ftype = m.from_buffer(base64data)
                    mag_ftype = mag.from_buffer(base64data)
                    if re.match(PAT_EXEHEADER, base64data) and re.search(PAT_EXEDOS, base64data):
                        b64_file_name = f"{sha256hash[0:10]}_b64_decoded_exe"
                        self.extract_file(
                            request,
                            base64data,
                            b64_file_name,
                            "Extracted b64 executable during FrankenStrings analysis",
                        )
                        results[sha256hash] = (
                            len(b64_string),
                            b64_string[0:50],
                            b"[Encoded PE file. See extracted files.]",
                            b"",
                        )
                        return results, pat
                    elif any(
                        (file_type in ftype and "octet-stream" not in ftype) or file_type in mag_ftype
                        for file_type in self.FILETYPES
                    ):
                        b64_file_name = f"{sha256hash[0:10]}_b64_decoded"
                        self.extract_file(
                            request, base64data, b64_file_name, "Extracted b64 file during FrankenStrings analysis"
                        )
                        results[sha256hash] = (
                            len(b64_string),
                            b64_string[0:50],
                            b"[Possible file contents. See extracted files.]",
                            b"",
                        )
                        return results, pat

                # See if any IOCs in decoded data
                pat = self.ioc_to_tag(base64data, patterns, taglist=True)
                # Filter printable characters then put in results
                asc_b64 = bytes(i for i in base64data if 31 < i < 127)
                if len(asc_b64) > 0:
                    # If patterns exists, report. If not, report only if string looks interesting
                    if len(pat) > 0:
                        results[sha256hash] = (len(b64_string), b64_string[0:50], asc_b64, base64data)
                    # PDF and Office documents have too many FPS
                    elif not self.sample_type.startswith("document/office") and not self.sample_type.startswith(
                        "document/pdf"
                    ):
                        # If data has length greater than 50, and unique character to length ratio is high
                        uniq_char = set(asc_b64)
                        if len(uniq_char) > 12 and len(re.sub(b"[^A-Za-z0-9]+", b"", asc_b64)) > 50:
                            results[sha256hash] = (len(b64_string), b64_string[0:50], asc_b64, base64data)
                # If not all printable characters but IOCs discovered, extract to file
                elif len(pat) > 0:
                    b64_file_name = f"{sha256hash[0:10]}_b64_decoded"
                    self.extract_file(
                        request, base64data, b64_file_name, "Extracted b64 file during FrankenStrings analysis"
                    )
                    results[sha256hash] = (
                        len(b64_string),
                        b64_string[0:50],
                        b"[IOCs discovered with other non-printable data. " b"See extracted files.]",
                        b"",
                    )

            except Exception:
                return results, pat
        return results, pat

    def unhexlify_ascii(
        self, request: ServiceRequest, data: bytes, filetype: str, patterns: PatternMatch
    ) -> Tuple[bool, Tags, Dict[str, Tuple[bytes, bytes, str]]]:
        """Plain ascii hex conversion.

        Args:
            request: AL request object (for submitting extracted files to AL when needed).
            data: Data to examine.
            filetype: request file type.
            patterns: Frankenstrings patterns object.

        Returns:
            If a file was extracted, tags, and xor results
        """
        tags: Tags = {}
        xor: Dict[str, Tuple[bytes, bytes, str]] = {}
        if len(data) % 2 != 0:
            data = data[:-1]
        # noinspection PyBroadException
        try:
            binstr = binascii.unhexlify(data)
        except Exception:
            return False, tags, xor
        # If data has less than 7 uniq chars return
        uniq_char = set(binstr)
        if len(uniq_char) < 7:
            return False, tags, xor
        # If data is greater than 500 bytes create extracted file
        if len(binstr) > 500:
            if len(uniq_char) < 20:
                return False, tags, xor
            sha256hash = hashlib.sha256(binstr).hexdigest()
            asciihex_file_name = f"{sha256hash[0:10]}_asciihex_decoded"
            self.extract_file(
                request, binstr, asciihex_file_name, "Extracted ascii-hex file during FrankenStrings analysis"
            )
            return True, tags, xor
        # Else look for patterns
        tags = self.ioc_to_tag(binstr, patterns, taglist=True, st_max_length=1000)
        if tags:
            return False, tags, xor
        # Else look for small XOR encoded strings in code files
        if 20 < len(binstr) <= 128 and filetype.startswith("code/"):
            xresult: List[Tuple[str, str, bytes]] = bbcrack(binstr, level="small_string")
            if len(xresult) > 0:
                for transform, regex, match in xresult:
                    if regex.startswith("EXE_"):
                        # noinspection PyTypeChecker
                        xor["file.string.blacklisted"] = (data, match, transform)
                    else:
                        # noinspection PyTypeChecker
                        xor[regex] = (data, match, transform)
                    return False, tags, xor
        return False, tags, xor

    # Executable extraction
    def pe_dump(
        self,
        request: ServiceRequest,
        data: bytes,
        offset: int,
        file_string: str,
        msg: str,
        fail_on_except: bool = False,
    ) -> bool:
        """Use PEFile application to find the end of the file (biggest section length wins).

        Args:
            request: AL request object (for submitting extracted PE AL).
            temp_file: Sample file with possible embedded PE.
            offset: Offset of temp_file where PE file begins.
            file_string: String appended to extracted PE file name.
            msg: File extraction message
            fail_on_except: When False, if PEFile fails, extract from offset all the way to the end of the initial file.

        Returns:
            True if PE extracted.
        """
        pe_extract = None
        mm = None

        # Dump data to a temporary file
        pe_sha256 = hashlib.sha256(data).hexdigest()
        temp_file = os.path.join(self.working_directory, f"EXE_TEMP_{pe_sha256}")
        with open(temp_file, "wb") as f:
            f.write(data)

        try:
            with open(temp_file, "rb") as f:
                mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)

            pedata = mm[offset:]

            # noinspection PyBroadException
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
                pe_file_name = f"{hashlib.sha256(pe_extract).hexdigest()[0:10]}_{file_string}"
                self.extract_file(request, pe_extract, pe_file_name, msg)
        except Exception:
            self.log.warning("Dumping PE file failed for {request.sha256}")
        finally:
            # noinspection PyBroadException
            try:
                if mm is not None:
                    mm.close()
            except Exception:
                pass

        return bool(pe_extract)

    # --- Results methods ----------------------------------------------------------------------------------------------

    def ascii_results(
        self, request: ServiceRequest, patterns: PatternMatch, max_length: int, st_max_size: int
    ) -> Optional[ResultSection]:
        """
        Finds and reports ASCII & Unicode IOC Strings.

        Args:
            request: AL request object with result section
            patterns: PatternMatch object

        Returns:
            The created result section (with request.result as its parent)
        """
        # Check the maximum length except for code files
        chkl = not self.sample_type.startswith("code")

        ascii_res = ResultSection(
            "The following IOC were found in plain text in the file:", body_format=BODY_FORMAT.MEMORY_DUMP
        )

        file_plainstr_iocs = self.ioc_to_tag(
            request.file_contents,
            patterns,
            ascii_res,
            taglist=True,
            check_length=chkl,
            strs_max_size=st_max_size,
            st_max_length=max_length,
        )

        for k, l in sorted(file_plainstr_iocs.items()):
            for i in sorted(l):
                ascii_res.add_line(f"Found {k.upper().replace('.', ' ')} string: {safe_str(i)}")
        for access_groups in re.finditer(
            rb"<key>keychain-access-groups</key>\s*<array>([\w\s.<>/]+)</array>", request.file_contents
        ):
            for string in re.finditer(rb"<string>([\w.]+)</string>", access_groups.group(1)):
                ascii_res.add_tag("file.string.extracted", string.group(1))
                ascii_res.add_line(f"Found FILE STRING EXTRACTED string: {safe_str(string.group(1))}")
        if ascii_res.tags:
            request.result.add_section(ascii_res)
            return ascii_res
        return None

    def embedded_pe_results(self, request: ServiceRequest) -> Optional[ResultSection]:
        """
        Finds, extracts and reports embedded executables

        Args:
            request: AL request object with result section

        Returns:
            The result section (with request.result as its parent) if one is created
        """
        embedded_pe = False
        for pos_exe in re.findall(PAT_EXEHEADER, request.file_contents[1:]):
            if re.search(PAT_EXEDOS, pos_exe):
                embedded_pe = embedded_pe or self.pe_dump(
                    request,
                    pos_exe,
                    offset=0,
                    file_string="embed_pe",
                    msg="PE header strings discovered in sample",
                    fail_on_except=True,
                )
        # Look for reversed PE files
        reversed_pe = False
        for pos_exe in re.findall(PAT_EXEHEADER, request.file_contents[::-1]):
            if re.search(PAT_EXEDOS, pos_exe):
                reversed_pe = reversed_pe or self.pe_dump(
                    request,
                    pos_exe,
                    offset=0,
                    file_string="reverse_pe",
                    msg="Reversed PE header strings discovered in sample",
                    fail_on_except=True,
                )
        # Report embedded PEs if any are found
        if embedded_pe or reversed_pe:
            return ResultSection(
                "Embedded PE header discovered in sample. See extracted files.",
                heuristic=Heuristic(3, signature="reversed" if reversed_pe else None),
                parent=request.result,
            )
        return None

    def base64_results(self, request: ServiceRequest, patterns: PatternMatch) -> Optional[ResultSection]:
        """
        Finds and reports Base64 encoded text

        Args:
            request: AL request object with result section
            patterns: PatternMatch object

        Returns:
            The result section (with request.result as its parent) if one is created
        """
        b64_al_results: List[Tuple[B64Result, Tags]] = []
        b64_matches: Set[bytes] = set()

        # Base64 characters with possible space, newline characters and HTML line feeds (&#xA; or &#10;)
        for b64_match in re.findall(BASE64_RE, request.file_contents):
            b64_string = (
                b64_match.replace(b"\n", b"")
                .replace(b"\r", b"")
                .replace(b" ", b"")
                .replace(b"&#xA;", b"")
                .replace(b"&#10;", b"")
            )
            if b64_string in b64_matches:
                continue
            if b64_string.endswith(b"VT") and b"A" * 10 in b64_string and len(b64_string) > 500:
                # reversed base64 encoded pe file
                b64_string = b64_string[::-1]
            b64_matches.add(b64_string)
            uniq_char = set(b64_string)
            if len(uniq_char) > 6:
                b64result, tags = self.b64(request, b64_string, patterns)
                if len(b64result) > 0:
                    b64_al_results.append((b64result, tags))

        # UTF-16 strings
        for ust in strings.extract_unicode_strings(request.file_contents, n=self.st_min_length):
            for b64_match in re.findall(BASE64_RE, ust.s):
                b64_string = b64_match.replace(b"\n", b"").replace(b"\r", b"").replace(b" ", b"")
                uniq_char = set(b64_string)
                if len(uniq_char) > 6:
                    b64result, tags = self.b64(request, b64_string, patterns)
                    if len(b64result) > 0:
                        b64_al_results.append((b64result, tags))

        # Report B64 Results
        if len(b64_al_results) > 0:
            b64_ascii_content: List[bytes] = []
            b64_res = ResultSection("Base64 Strings:", heuristic=Heuristic(1), parent=request.result)
            b64index = 0
            for b64dict, tags in b64_al_results:
                for ttype, values in tags.items():
                    for v in values:
                        b64_res.add_tag(ttype, v)
                for b64k, b64l in b64dict.items():
                    b64index += 1
                    sub_b64_res = ResultSection(f"Result {b64index}", parent=b64_res)
                    sub_b64_res.add_line(f"BASE64 TEXT SIZE: {b64l[0]}")
                    sub_b64_res.add_line(f"BASE64 SAMPLE TEXT: {safe_str(b64l[1])}[........]")
                    sub_b64_res.add_line(f"DECODED SHA256: {b64k}")
                    subb_b64_res = ResultSection(
                        "DECODED ASCII DUMP:", body_format=BODY_FORMAT.MEMORY_DUMP, parent=sub_b64_res
                    )
                    subb_b64_res.add_line(truncate(safe_str(b64l[2])))
                    if b64l[2] == b"[Encoded PE file. See extracted files.]":
                        sub_b64_res.set_heuristic(11)
                    if b64l[2] not in [
                        b"[Possible file contents. See extracted files.]",
                        b"[IOCs discovered with other non-printable data. See extracted files.]",
                    ]:
                        b64_ascii_content.append(b64l[3])
            # Write all non-extracted decoded b64 content to file
            if len(b64_ascii_content) > 0:
                all_b64 = b"\n".join(b64_ascii_content)
                b64_all_sha256 = hashlib.sha256(all_b64).hexdigest()
                self.extract_file(
                    request, all_b64, f"all_b64_{b64_all_sha256[:7]}.txt", "all misc decoded b64 from sample"
                )
            return b64_res
        return None

    def bbcrack_results(self, request: ServiceRequest) -> Optional[ResultSection]:
        """
        Balbuzard's bbcrack XOR'd strings to find embedded patterns/PE files of interest

        Args:
            request: AL request object with result section

        Returns:
            The result section (with request.result as its parent) if one is created
        """
        x_res = ResultSection("BBCrack XOR'd Strings:", body_format=BODY_FORMAT.MEMORY_DUMP, heuristic=Heuristic(2))
        if request.deep_scan:
            xresult = bbcrack(request.file_contents, level=2)
        else:
            xresult = bbcrack(request.file_contents, level=1)
        xformat_string = "%-20s %-7s %-7s %-50s"
        xor_al_results = []
        for transform, regex, offset, score, smatch in xresult:
            if regex == "EXE_HEAD":
                pe_extracted = self.pe_dump(
                    request,
                    smatch,
                    offset,
                    file_string="xorpe_decoded",
                    msg="Extracted xor file during FrakenStrings analysis.",
                )
                if pe_extracted:
                    xor_al_results.append(
                        xformat_string % (str(transform), offset, score, "[PE Header Detected. See Extracted files]")
                    )
            else:
                if not regex.startswith("EXE_"):
                    x_res.add_tag(self.BBCRACK_TO_TAG.get(regex, regex), smatch)
                xor_al_results.append(xformat_string % (str(transform), offset, score, safe_str(smatch)))
        # Result Graph:
        if len(xor_al_results) > 0:
            xcolumn_names = ("Transform", "Offset", "Score", "Decoded String")
            x_res.add_line(xformat_string % xcolumn_names)
            x_res.add_line(xformat_string % tuple("-" * len(s) for s in xcolumn_names))
            x_res.add_lines(xor_al_results)
            request.result.add_section(x_res)
            return x_res
        return None

    def unicode_results(self, request: ServiceRequest, patterns: PatternMatch) -> Optional[ResultSection]:
        """
        Finds and report unicode encoded strings

        Args:
            request: AL request object with result section
            patterns: PatternMatch object

        Returns:
            The result section (with request.result as its parent) if one is created
        """
        unicode_al_results: Dict[str, Tuple[bytes, bytes]] = {}
        dropped_unicode: List[Tuple[str, str]] = []
        for hes in self.HEXENC_STRINGS:
            if re.search(re.escape(hes) + b"[A-Fa-f0-9]{2}", request.file_contents):
                dropped = self.decode_encoded_udata(request, hes, request.file_contents, unicode_al_results)
                for uhash in dropped:
                    dropped_unicode.append((uhash, safe_str(hes)))

        # Report Unicode Encoded Data:
        unicode_heur = Heuristic(5, frequency=len(dropped_unicode)) if dropped_unicode else None
        unicode_emb_res = ResultSection(
            "Found Unicode-Like Strings in Non-Executable:", body_format=BODY_FORMAT.MEMORY_DUMP, heuristic=unicode_heur
        )
        for uhash, uenc in dropped_unicode:
            unicode_emb_res.add_line(
                f"Extracted over 50 bytes of possible embedded unicode with "
                f"{uenc} encoding. SHA256: {uhash}. See extracted files."
            )

        for unires_index, (sha256, (decoded, encoded)) in enumerate(unicode_al_results.items()):
            sub_uni_res = ResultSection(f"Result {unires_index}", parent=unicode_emb_res)
            sub_uni_res.add_line(f"ENCODED TEXT SIZE: {len(decoded)}")
            sub_uni_res.add_line(f"ENCODED SAMPLE TEXT: {safe_str(encoded)}[........]")
            sub_uni_res.add_line(f"DECODED SHA256: {sha256}")
            subb_uni_res = ResultSection("DECODED ASCII DUMP:", body_format=BODY_FORMAT.MEMORY_DUMP, parent=sub_uni_res)
            subb_uni_res.add_line("{}".format(safe_str(decoded)))
            # Look for IOCs of interest
            hits = self.ioc_to_tag(decoded, patterns, sub_uni_res, st_max_length=1000, taglist=True)
            if hits:
                sub_uni_res.set_heuristic(6)
                subb_uni_res.add_line("Suspicious string(s) found in decoded data.")
            else:
                sub_uni_res.set_heuristic(4)

        if unicode_al_results or dropped_unicode:
            request.result.add_section(unicode_emb_res)
            return unicode_emb_res
        return None

    def hex_results(self, request: ServiceRequest, patterns: PatternMatch) -> None:
        """
        Finds and reports long ascii hex strings

        Args:
            request: AL request object with result section
            patterns: PatternMatch object
        """
        asciihex_file_found = False
        asciihex_dict: Dict[str, Set[str]] = {}
        asciihex_bb_dict: Dict[str, Set[Tuple[bytes, bytes, str]]] = {}

        hex_pat = re.compile(b"((?:[0-9a-fA-F]{2}[\r]?[\n]?){16,})")
        for hex_match in re.findall(hex_pat, request.file_contents):
            hex_string = hex_match.replace(b"\r", b"").replace(b"\n", b"")
            afile_found, asciihex_results, xorhex_results = self.unhexlify_ascii(
                request, hex_string, request.file_type, patterns
            )
            if afile_found:
                asciihex_file_found = True
            for ascii_key, ascii_values in asciihex_results.items():
                asciihex_dict.setdefault(ascii_key, set())
                asciihex_dict[ascii_key].update(ascii_values)
            for xor_key, xor_results in xorhex_results.items():
                if xor_key.startswith("BB_"):
                    xor_key = xor_key.split("_", 1)[1]
                    asciihex_bb_dict.setdefault(xor_key, set())
                    asciihex_bb_dict[xor_key].add(xor_results)
                else:
                    asciihex_dict.setdefault(xor_key, set())
                    asciihex_dict[xor_key].add(safe_str(xor_results[1]))

        # Report Ascii Hex Encoded Data:
        if asciihex_file_found:
            asciihex_emb_res = ResultSection(
                "Found Large Ascii Hex Strings in Non-Executable:",
                body_format=BODY_FORMAT.MEMORY_DUMP,
                heuristic=Heuristic(7),
                parent=request.result,
            )
            asciihex_emb_res.add_line("Extracted possible ascii-hex object(s). See extracted files.")

        if asciihex_dict:
            # Different scores are used depending on whether the file is a document
            asciihex_res = ResultSection(
                "ASCII HEX DECODED IOC Strings:",
                body_format=BODY_FORMAT.MEMORY_DUMP,
                heuristic=Heuristic(10 if request.file_type.startswith("document") else 8),
                parent=request.result,
            )
            for key, hex_list in sorted(asciihex_dict.items()):
                for h in hex_list:
                    asciihex_res.add_line(f"Found {key.replace('_', ' ')} decoded HEX string: {safe_str(h)}")
                    asciihex_res.add_tag(key, h)

        if asciihex_bb_dict:
            asciihex_bb_res = ResultSection(
                "ASCII HEX AND XOR DECODED IOC Strings:", heuristic=Heuristic(9), parent=request.result
            )
            for xindex, (xkey, xset) in enumerate(sorted(asciihex_bb_dict.items())):
                for xresult in xset:
                    data, match, transform = xresult
                    asx_res = ResultSection(f"Result {xindex}", parent=asciihex_bb_res)
                    asx_res.add_line(
                        f"Found {xkey.replace('_', ' ')} decoded HEX string, masked with "
                        f"transform {safe_str(transform)}:"
                    )
                    asx_res.add_line("Decoded XOR string:")
                    asx_res.add_line(safe_str(match))
                    asx_res.add_line("Original ASCII HEX String:")
                    asx_res.add_line(safe_str(data))
                    asciihex_bb_res.add_tag(xkey, match)

    # --- Execute ------------------------------------------------------------------------------------------------------

    def execute(self, request: ServiceRequest) -> None:
        """Main Module. See README for details."""
        request.result = Result()
        patterns = PatternMatch()
        self.sample_type = request.file_type
        self.excess_extracted = 0

        max_size = request.get_param("max_file_size")
        max_length = request.get_param("max_string_length")
        st_max_size = self.config.get("st_max_size", 0)
        bb_max_size = self.config.get("bb_max_size", 85000)

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

        # Begin analysis
        if (len(request.file_contents) or 0) >= max_size or self.sample_type.startswith("archive/"):
            # No analysis is done if the file is an archive or too large
            return

        self.ascii_results(request, patterns, max_length, st_max_size)
        self.embedded_pe_results(request)

        # Possible encoded strings -- all sample types except code/* (code is handled by deobfuscripter service)
        # Include html and xml for base64
        if not self.sample_type.startswith("code") or self.sample_type in ("code/html", "code/xml"):
            self.base64_results(request, patterns)
        if not self.sample_type.startswith("code"):
            if (len(request.file_contents) or 0) < bb_max_size:
                self.bbcrack_results(request)
            # Other possible encoded strings -- all sample types but code and executables
            if not self.sample_type.startswith("executable"):
                self.unicode_results(request, patterns)
                # Go over again, looking for long ASCII-HEX character strings
                if not self.sample_type.startswith("document/office"):
                    self.hex_results(request, patterns)

        try:
            md = Multidecoder()
            tree = md.scan(request.file_contents)
            json = tree_to_json(tree)
            filename = request.sha256[:8] + '_md.json'
            filepath = os.path.join(self.working_directory, filename)
            with open(filepath, 'w') as f:
                f.write(json)
            request.add_supplementary(filepath, filename, 'Multidecoder json')
        except Exception:
            pass

        if self.excess_extracted:
            self.log.warning(
                f"Too many files extracted from {request.sha256}, " f"{self.excess_extracted} files were not extracted"
            )
            request.result.add_section(
                ResultSection(f"Over extraction limit: " f"{self.excess_extracted} files were not extracted")
            )
