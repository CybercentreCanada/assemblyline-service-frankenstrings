import binascii
import hashlib
import magic
import os
import re
import unicodedata

from collections import Counter

from assemblyline.common.str_utils import safe_str
from assemblyline_v4_service.common.result import ResultSection, BODY_FORMAT, Heuristic


class CrowBar(object):
    FILETYPES = ['application',
                 'document',
                 'exec',
                 'image',
                 'Microsoft',
                 'text',
                 ]
    VALIDCHARS = b' 0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~'
    BINCHARS = bytes(list(set(range(0, 256)) - set(VALIDCHARS)))

    def __init__(self):
        self.max_attempts = None
        self.files_extracted = None
        self.wd = None
        self.hashes = None

    # --- Support Modules ----------------------------------------------------------------------------------------------

    def printable_ratio(self, text):
        return float(float(len(text.translate(None, self.BINCHARS))) / float(len(text)))

    @staticmethod
    def add1b(s, k):
        return bytes([(c + k) & 0xff for c in s])

    def charcode(self, text):
        output = None
        arrayofints = list(filter(lambda n: n < 256,
                                  map(int, re.findall(r'(\d+)', str(re.findall(rb'\D{1,2}\d{2,3}', text))))))
        if len(arrayofints) > 20:
            s1 = bytes(arrayofints)
            if self.printable_ratio(s1) > .75 and (float(len(s1)) / float(len(text))) > .10:
                # if the output is mostly readable and big enough
                output = s1

        return output

    @staticmethod
    def charcode_hex(text):
        output = None
        s1 = text
        enc_str = [b'\\u', b'%u', b'\\x', b'0x']

        for encoding in enc_str:
            char_len = [(16, re.compile(rb'(?:' + re.escape(encoding) + b'[A-Fa-f0-9]{16})+')),
                        (8, re.compile(rb'(?:' + re.escape(encoding) + b'[A-Fa-f0-9]{8})+')),
                        (4, re.compile(rb'(?:' + re.escape(encoding) + b'[A-Fa-f0-9]{4})+')),
                        (2, re.compile(rb'(?:' + re.escape(encoding) + b'[A-Fa-f0-9]{2})+'))]

            for r in char_len:
                hexchars = set(re.findall(r[1], text))

                for hc in hexchars:
                    data = hc
                    decoded = b''
                    if r[0] == 2:
                        while data != b'':
                            decoded += binascii.a2b_hex(data[2:4])
                            data = data[4:]
                    if r[0] == 4:
                        while data != b'':
                            decoded += binascii.a2b_hex(data[4:6]) + binascii.a2b_hex(data[2:4])
                            data = data[6:]
                    if r[0] == 8:
                        while data != b'':
                            decoded += binascii.a2b_hex(data[8:10]) + binascii.a2b_hex(data[6:8]) + \
                                       binascii.a2b_hex(data[4:6]) + binascii.a2b_hex(data[2:4])
                            data = data[10:]
                    if r[0] == 16:
                        while data != b'':
                            decoded += binascii.a2b_hex(data[16:18]) + binascii.a2b_hex(data[14:16]) + \
                                       binascii.a2b_hex(data[12:14]) + binascii.a2b_hex(data[10:12]) + \
                                       binascii.a2b_hex(data[8:10]) + binascii.a2b_hex(data[6:8]) + \
                                       binascii.a2b_hex(data[4:6]) + binascii.a2b_hex(data[2:4])
                            data = data[18:]

                    # Remove trailing NULL bytes
                    final_dec = re.sub(b'[\x00]*$', b'', decoded)
                    s1 = s1.replace(hc, final_dec)

        if s1 != text:
            output = s1

        return output

    @staticmethod
    def chr_decode(text):
        output = text
        for fullc, c in re.findall(rb'(chr[bw]?\(([0-9]{1,3})\))', output, re.I):
            # noinspection PyBroadException
            try:
                output = re.sub(re.escape(fullc), '"{}"'.format(chr(int(c))).encode('utf-8'), output)
            except Exception:
                continue
        if output == text:
            output = None
        return output

    @staticmethod
    def string_replace(text):
        output = None
        if b'replace(' in text.lower():
            # Process string with replace functions calls
            # Such as "SaokzueofpigxoFile".replace(/ofpigx/g, "T").replace(/okzu/g, "v")
            s1 = text
            # Find all occurrences of string replace (JS)
            for strreplace in [o[0] for o in
                               re.findall(rb'(["\'][^"\']+["\']((\.replace\([^)]+\))+))', s1, flags=re.I)]:
                s2 = strreplace
                # Extract all substitutions
                for str1, str2 in re.findall(rb'\.replace\([/\'"]([^,]+)[/\'\"]g?\s*,\s*[\'\"]([^)]*)[\'\"]\)',
                                             s2, flags=re.I):
                    # Execute the substitution
                    s2 = s2.replace(str1, str2)
                # Remove the replace calls from the layer (prevent accidental substitutions in the next step)
                s2 = s2[:s2.lower().index(b'.replace(')]
                s1 = s1.replace(strreplace, s2)

            # Process global string replace
            replacements = [q for q in re.findall(rb'replace\(\s*/([^)]+)/g?, [\'"]([^\'"]*)[\'"]', s1)]
            for str1, str2 in replacements:
                s1 = s1.replace(str1, str2)
            # Process VB string replace
            replacements = [q for q in re.findall(rb'Replace\(\s*["\']?([^,"\']*)["\']?\s*,\s*["\']?'
                                                  rb'([^,"\']*)["\']?\s*,\s*["\']?([^,"\']*)["\']?', s1)]
            for str1, str2, str3 in replacements:
                s1 = s1.replace(str1, str1.replace(str2, str3))
            output = re.sub(rb'\.replace\(\s*/([^)]+)/g?, [\'"]([^\'"]*)[\'"]\)', b'', s1)
        return output

    def b64decode_str(self, text):
        output = None
        b64str = re.findall(b'((?:[A-Za-z0-9+/]{3,}={0,2}(?:&#[x1][A0];)?[\r]?[\n]?){6,})', text)
        s1 = text
        for bmatch in b64str:
            s = bmatch.replace(b'\n',
                               b'').replace(b'\r', b'').replace(b' ', b'').replace(b'&#xA;', b'').replace(b'&#10;', b'')
            uniq_char = set(s)
            if len(uniq_char) > 6:
                if len(s) >= 16 and len(s) % 4 == 0:
                    try:
                        d = binascii.a2b_base64(s)
                    except binascii.Error:
                        continue
                    m = magic.Magic(mime=True)
                    mag = magic.Magic()
                    ftype = m.from_buffer(d)
                    mag_ftype = mag.from_buffer(d)
                    sha256hash = hashlib.sha256(d).hexdigest()
                    if sha256hash not in self.hashes:
                        if len(d) > 500:
                            for ft in self.FILETYPES:
                                if (ft in ftype and 'octet-stream' not in ftype) or ft in mag_ftype:
                                    b64_file_name = f"{sha256hash[0:10]}_cb_b64_decoded"
                                    b64_file_path = os.path.join(self.wd, b64_file_name)
                                    with open(b64_file_path, 'wb') as b64_file:
                                        b64_file.write(d)
                                    self.files_extracted.add(b64_file_path)
                                    self.hashes.add(sha256hash)
                                    break
                        uniq_char = set(d)
                        if len(uniq_char) > 6 and all(31 < c < 127 for c in d) and len(re.sub(rb"\s", b"", d)) > 14:
                            s1 = s1.replace(bmatch, d)

        if s1 != text:
            output = s1
        return output

    @staticmethod
    def vars_of_fake_arrays(text):

        output = None
        replacements = re.findall(rb'var\s+([^\s=]+)\s*=\s*\[([^\]]+)\]\[(\d+)\]', text)
        if len(replacements) > 0:
            #    ,- Make sure we do not process these again
            s1 = re.sub(rb'var\s+([^=]+)\s*=', rb'XXX \1 =', text)
            for varname, array, pos in replacements:
                try:
                    value = re.split(rb'\s*,\s*', array)[int(pos)]
                except IndexError:
                    # print '[' + array + '][' + pos + ']'
                    break
                s1 = s1.replace(varname, value)
            if s1 != text:
                output = s1
        return output

    @staticmethod
    def array_of_strings(text):
        # noinspection PyBroadException
        try:
            output = None
            replacements = re.findall(rb'var\s+([^\s=]+)\s*=\s*\[([^\]]+)\]\s*;', text)
            if len(replacements) > 0:
                #    ,- Make sure we do not process these again
                s1 = text
                for varname, values in replacements:
                    occurences = [int(x) for x in re.findall(varname + rb'\s*\[(\d+)\]', s1)]
                    for i in occurences:
                        try:
                            s1 = re.sub(varname + rb'\s*\[(%d)\]' % i, values.split(b',')[i], s1)
                        except IndexError:
                            # print '[' + array + '][' + pos + ']'
                            break
                if s1 != text:
                    output = s1
        except Exception:
            output = None
        return output

    @staticmethod
    def concat_strings(text):
        output = None
        # Line continuation character in VB -- '_'
        s1 = re.sub(rb'[\'"][\s\n_]*?[+&][\s\n_]*[\'"]', b'', text)
        if s1 != text:
            output = s1

        return output

    @staticmethod
    def str_reverse(text):
        output = None
        s1 = text
        # VBA format StrReverse("[text]")
        replacements = re.findall(rb'(StrReverse\("(.+?(?="\))))', s1)
        for full, st in replacements:
            reversed_st = full.replace(st, st[::-1]).replace(b"StrReverse(", b"")[:-1]
            s1 = s1.replace(full, reversed_st)
        if s1 != text:
            output = s1
        return output

    @staticmethod
    def powershell_vars(text):
        output = None
        replacements_string = re.findall(rb'(\$(?:\w+|{[^\}]+\}))\s*=[^=]\s*[\"\']([^\"\']+)[\"\']', text)
        replacements_func = re.findall(rb'(\$(?:\w+|{[^\}]+\}))\s*=\s*([^=\"\'\s$]{3,50})[\s]', text)
        if len(replacements_string) > 0 or len(replacements_func) > 0:
            #    ,- Make sure we do not process these again
            s1 = re.sub(rb'\$((?:\w+|{[^\}]+\}))\s*=', rb'\$--\1 =', text)
            for varname, string in replacements_string:
                s1 = s1.replace(varname, string)
            for varname, string in replacements_func:
                s1 = s1.replace(varname, string)
            if output != text:
                output = s1

        return output

    @staticmethod
    def powershell_carets(text):
        output = text
        for full in re.findall(rb'"(?:[^"]+[A-Za-z0-9]+\^[A-Za-z0-9]+[^"]+)+"', text):
            output = output.replace(full, full.replace(b"^", b""))
        if output == text:
            output = None
        return output

    # noinspection PyBroadException
    @staticmethod
    def msoffice_embedded_script_string(text):
        try:
            scripts = {}
            output = text
            # bad, prevent false var replacements like YG="86"
            # Replace regular variables
            replacements = re.findall(rb'^(\s*(\w+)\s*=\s*\w*\s*\+?\s(["\'])(.+)["\']\s*\+\s*vbCrLf\s*$)', output, re.M)
            if len(replacements) > 0:
                for full, vn, delim, value in replacements:
                    scripts.setdefault(vn, [])
                    scripts[vn].append(value.replace(delim + delim, delim))
                    output = output.replace(full, b'<crowbar:msoffice_embedded_script_string_var_assignment>')

            for script_var, script_lines in scripts.items():
                new_script_name = b'new_script__' + script_var
                output = re.sub(rb'(.+)\b' + script_var + rb'\b', b'\\1' + new_script_name, output)
                output += b"\n\n\n' ---- script referenced by \"" + new_script_name + b"\" ----\n\n\n"
                output += b"\n".join(script_lines)

            if output == text:
                output = None

        except Exception:
            output = None
        return output

    @staticmethod
    def mswordmacro_vars(text):
        # noinspection PyBroadException
        try:
            output = text
            # prevent false var replacements like YG="86"
            # Replace regular variables
            replacements = re.findall(rb'^\s*((?:Const[\s]*)?(\w+)\s*='
                                      rb'\s*((?:["][^"]+["]|[\'][^\']+[\']|[0-9]*)))[\s\r]*$',
                                      output, re.MULTILINE | re.DOTALL)
            if len(replacements) > 0:
                for full, varname, value in replacements:
                    if len(re.findall(rb'\b' + varname + rb'\b', output)) == 1:
                        # If there is only one instance of these, it's probably noise.
                        output = output.replace(full, b'<crowbar:mswordmacro_unused_variable_assignment>')
                    else:
                        final_val = value.replace(b'"', b"")
                        # Stacked strings
                        # b = "he"
                        # b = b & "llo "
                        # b = b & "world!"
                        stacked = re.findall(rb'^\s*((' + varname + rb')\s*=\s*('
                                             + varname + rb')\s*[+&]\s*((?:["][^"]+["]|[\'][^\']+[\'])))[\s\r]*$',
                                             output, re.MULTILINE | re.DOTALL)
                        if len(stacked) > 0:
                            for sfull, varname, varname_b, val in stacked:
                                final_val += val.replace(b'"', b"")
                                output = output.replace(sfull, b'<crowbar:mswordmacro_var_assignment>')
                        output = output.replace(full, b'<crowbar:mswordmacro_var_assignment>')
                        # If more than a of the variable name left, the assumption is that this did not
                        # work according to plan, so just replace a few for now.
                        output = re.sub(rb'(\b' + re.escape(varname) +
                                        rb'(?!\s*(?:=|[+&]\s*' + re.escape(varname) + rb'))\b)',
                                        b'"' + final_val + b'"',
                                        output, count=5)

            # Remaining stacked strings
            replacements = re.findall(rb'^\s*((\w+)\s*=\s*(\w+)\s*[+&]\s*((?:["][^"]+["]|[\'][^\']+[\'])))[\s\r]*$',
                                      output, re.MULTILINE | re.DOTALL)
            replacements_vars = set([x[1] for x in replacements])
            for v in replacements_vars:
                final_val = b""
                for full, varname, varname_b, value in replacements:
                    if varname != v:
                        continue
                    final_val += value.replace(b'"', b"")
                    output = output.replace(full, b'<crowbar:mswordmacro_var_assignment>')
                output = re.sub(rb'(\b' + v +
                                rb'(?!\s*(?:=|[+&]\s*' + v + rb'))\b)',
                                b'"' + final_val + b'"',
                                output, count=5)

            if output == text:
                output = None

        except Exception:
            output = None
        return output

    def simple_xor_function(self, text):
        output = None
        xorstrings = re.findall(rb'(\w+\("((?:[0-9A-Fa-f][0-9A-Fa-f])+)"\s*,\s*"([^"]+)"\))', text)
        option_a = []
        option_b = []
        s1 = text
        for f, x, k in xorstrings:
            res = self.xor_with_key(binascii.a2b_hex(x), k)
            if self.printable_ratio(res) == 1:
                option_a.append((f, x, k, res))
                # print 'A:',f,x,k, res
            else:
                option_a.append((f, x, k, None))
            # try by shifting the key by 1
            res = self.xor_with_key(binascii.a2b_hex(x), k[1:] + k[0])
            if self.printable_ratio(res) == 1:
                option_b.append((f, x, k, res))
                # print 'B:',f,x,k, res
            else:
                option_b.append((f, x, k, None))

        xorstrings = []
        if None not in map(lambda y: y[3], option_a):
            xorstrings = option_a
        elif None not in map(lambda z: z[3], option_b):
            xorstrings = option_b

        for f, x, k, r in xorstrings:
            if r is not None:
                s1 = s1.replace(f, b'"' + r + b'"')

        if text != s1:
            output = s1
        return output

    @staticmethod
    def xor_with_key(s, k):
        return bytes([a ^ b for a, b in zip(s, (len(s) // len(k) + 1) * k)])

    @staticmethod
    def zp_xor_with_key(s, k):
        return bytes([a if a == 0 or a == b else a ^ b for a, b in zip(s, (len(s) // len(k) + 1) * k)])

    @staticmethod
    def clean_up_final_layer(text):
        output = re.sub(rb'\r', b'', text)
        output = re.sub(rb'<crowbar:[^>]+>\n?', b'', output)
        return output

    # --- Main Module --------------------------------------------------------------------------------------------------
    def hammertime(self, max_attempts, raw, before, patterns, wd, deep_scan=False):
        """Iterate through different decoding mechanisms in attempt to extract embedded IOCs in file content.

        Args:
            max_attempts: Number of iterations data should undertake.
            raw: Data to be examined.
            before: List of IOCs in raw data.
            patterns: FrankenStrings Patterns() object.
            wd: Directory where temporary content should be stored.

        Returns:
            If new IOCs found: AL result object, final decoded data, list of file names of extracted content.
            Else: None for all values.
        """
        self.max_attempts = max_attempts
        self.wd = wd
        self.files_extracted = set()
        self.hashes = set()
        al_res = None
        clean = None
        layers_list = []
        layer = raw
        techniques = [
            ('CHR and CHRB decode', self.chr_decode),
            ('String replace', self.string_replace),
            ('Concat strings', self.concat_strings),
            ('Powershell carets', self.powershell_carets),
            ('Array of strings', self.array_of_strings),
            ('Fake array vars', self.vars_of_fake_arrays),
            ('Reverse strings', self.str_reverse),
            ('B64 Decode', self.b64decode_str),
            ('Simple XOR function', self.simple_xor_function),
        ]
        second_pass = [
            ('MSOffice Embedded script', self.msoffice_embedded_script_string),
            ('MSWord macro vars', self.mswordmacro_vars),
            ('Powershell vars', self.powershell_vars),
        ]
        final_pass = [
            ('Charcode', self.charcode),
            ('Charcode hex', self.charcode_hex)
        ]

        idx = 0
        first_pass_len = len(techniques)
        layers_count = 0
        while True:
            if idx > self.max_attempts:
                final_pass.extend(techniques)
                for name, technique in final_pass:
                    res = technique(layer)
                    if res:
                        layers_list.append((name, res))
                break
            for name, technique in techniques:
                res = technique(layer)
                if res:
                    layers_list.append((name, res))
                    # Looks like it worked, restart with new layer
                    layer = res
            # If the layers haven't changed in a passing, break
            if layers_count == len(layers_list):
                if len(techniques) != first_pass_len:
                    final_pass.extend(techniques)
                    for name, technique in final_pass:
                        res = technique(layer)
                        if res:
                            layers_list.append((name, res))
                    break
                else:
                    for x in second_pass:
                        techniques.insert(0, x)
            layers_count = len(layers_list)
            idx += 1

        if len(layers_list) > 0:
            num_layers = len(layers_list)
            heur_id = None
            if num_layers < 5:
                heur_id = 11
            elif num_layers < 10:
                heur_id = 12
            elif num_layers < 50:
                heur_id = 13
            elif num_layers < 100:
                heur_id = 14
            elif num_layers >= 100:
                heur_id = 15
            clean = self.clean_up_final_layer(layers_list[-1][1])
            if clean != raw:
                pat_values = patterns.ioc_match(clean, bogon_ip=True, just_network=False)
                diff_tags = {}

                for k, val in pat_values.items():
                    if val == "":
                        asc_asc = unicodedata.normalize('NFKC', val).encode('ascii', 'ignore')
                        if asc_asc not in before:
                            diff_tags.setdefault(k, [])
                            diff_tags[k].append(asc_asc)
                    else:
                        for v in val:
                            if v not in before:
                                diff_tags.setdefault(k, [])
                                diff_tags[k].append(v)

                al_res = (ResultSection("CrowBar Plugin Detected Possible Obfuscated Script:"))
                mres = (ResultSection("The following CrowBar modules made deofuscation attempts:",
                                      parent=al_res))
                if heur_id:
                    mres.set_heuristic(heur_id)

                lcount = Counter([x[0] for x in layers_list])
                for l, c in lcount.items():
                    mres.add_line(f"{l}, {c} time(s).")

                # Look for all IOCs in final layer
                if len(diff_tags) > 0:
                    ioc_new = ResultSection("New IOCs found after de-obfustcation", parent=al_res,
                                            body_format=BODY_FORMAT.MEMORY_DUMP, heuristic=Heuristic(16))
                    for ty, val in diff_tags.items():
                        for v in val:
                            ioc_new.add_line(f"Found {ty.upper().replace('.', ' ')}: {safe_str(v)}")
                            ioc_new.add_tag(ty, v)

                # Display final layer
                ResultSection(f"First 500 bytes of the final layer:", body=safe_str(clean[:500]),
                              body_format=BODY_FORMAT.MEMORY_DUMP, parent=al_res)

                if len(self.files_extracted) > 0:
                    ResultSection("Deobfuscated code of interest extracted in isolation. See extracted files.",
                                  heuristic=Heuristic(17), parent=al_res)

        return al_res, clean, self.files_extracted
