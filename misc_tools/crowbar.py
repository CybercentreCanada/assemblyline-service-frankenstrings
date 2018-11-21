from assemblyline.al.common.result import ResultSection, SCORE, TAG_TYPE, TAG_WEIGHT, TEXT_FORMAT
from collections import Counter
import binascii
import hashlib
import magic
import os
import re
import unicodedata


class CrowBar(object):
    FILETYPES = ['application',
                      'document',
                      'exec',
                      'image',
                      'Microsoft',
                      'text',
                      ]
    VALIDCHARS = ' 0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~'
    BINCHARS = ''.join([c for c in map(chr, range(0, 256)) if c not in VALIDCHARS])

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
        return ''.join([chr((ord(c) + k) & 0xff) for c in s])

    def charcode(self, text):
        output = None
        arrayofints = filter(lambda n: n < 256,
                             map(int, re.findall('(\d+)', str(re.findall('\D{1,2}\d{2,3}', text)))))
        if len(arrayofints) > 20:
            s1 = ''.join(map(chr, arrayofints))
            if self.printable_ratio(s1) > .75 and (float(len(s1)) / float(len(text))) > .10:
                # if the output is mostly readable and big enough
                output = s1

        return output

    def charcode_hex(self, text):
        output = None
        s1 = text
        enc_str = ['\u', '%u', '\\x', '0x']

        for encoding in enc_str:
            char_len = [(16, re.compile(r'(?:' + re.escape(encoding) + '[A-Fa-f0-9]{16})+')),
                        (8, re.compile(r'(?:' + re.escape(encoding) + '[A-Fa-f0-9]{8})+')),
                        (4, re.compile(r'(?:' + re.escape(encoding) + '[A-Fa-f0-9]{4})+')),
                        (2, re.compile(r'(?:' + re.escape(encoding) + '[A-Fa-f0-9]{2})+'))]

            for r in char_len:
                hexchars = set(re.findall(r[1], text))

                for hc in hexchars:
                    data = hc
                    decoded = ''
                    if r[0] == 2:
                        while data != '':
                            decoded += binascii.a2b_hex(data[2:4])
                            data = data[4:]
                    if r[0] == 4:
                        while data != '':
                            decoded += binascii.a2b_hex(data[4:6]) + binascii.a2b_hex(data[2:4])
                            data = data[6:]
                    if r[0] == 8:
                        while data != '':
                            decoded += binascii.a2b_hex(data[8:10]) + binascii.a2b_hex(data[6:8]) + \
                                       binascii.a2b_hex(data[4:6]) + binascii.a2b_hex(data[2:4])
                            data = data[10:]
                    if r[0] == 16:
                        while data != '':
                            decoded += binascii.a2b_hex(data[16:18]) + binascii.a2b_hex(data[14:16]) + \
                                       binascii.a2b_hex(data[12:14]) + binascii.a2b_hex(data[10:12]) + \
                                       binascii.a2b_hex(data[8:10]) + binascii.a2b_hex(data[6:8]) + \
                                       binascii.a2b_hex(data[4:6]) + binascii.a2b_hex(data[2:4])
                            data = data[18:]

                    # Remove trailing NULL bytes
                    final_dec = re.sub('[\x00]*$', '', decoded)
                    s1 = s1.replace(hc, final_dec)

        if s1 != text:
            output = s1

        return output

    @staticmethod
    def chr_decode(text):
        output = text
        for fullc, c in re.findall(r'(chr[b]?\(([0-9]{1,3})\))', output, re.I):
            try:
               output = re.sub(re.escape(fullc), re.escape('{}' .format(chr(int(c)))), output)
            except:
                continue
        if output == text:
            output = None
        return output

    @staticmethod
    def string_replace(text):
        output = None
        if 'replace(' in text.lower():
            # Process string with replace functions calls
            # Such as "SaokzueofpigxoFile".replace(/ofpigx/g, "T").replace(/okzu/g, "v")
            s1 = text
            # Find all occurrences of string replace (JS)
            for strreplace in [o[0] for o in
                               re.findall('(["\'][^"\']+["\']((\.replace\([^)]+\))+))', s1, flags=re.I)]:
                s2 = strreplace
                # Extract all substitutions
                for str1, str2 in re.findall('\.replace\([/\'"]([^,]+)[/\'\"]g?\s*,\s*[\'\"]([^)]*)[\'\"]\)',
                                             s2, flags=re.I):
                    # Execute the substitution
                    s2 = s2.replace(str1, str2)
                # Remove the replace calls from the layer (prevent accidental substitutions in the next step)
                s2 = s2[:s2.lower().index('.replace(')]
                s1 = s1.replace(strreplace, s2)

            # Process global string replace
            replacements = [q for q in re.findall('replace\(\s*/([^)]+)/g?, [\'"]([^\'"]*)[\'"]', s1)]
            for str1, str2 in replacements:
                s1 = s1.replace(str1, str2)
            # Process VB string replace
            replacements = [q for q in re.findall('Replace\(\s*["\']?([^,"\']*)["\']?\s*,\s*["\']?([^,"\']*)["\']?\s*,\s*["\']?([^,"\']*)["\']?', s1)]
            for str1, str2, str3 in replacements:
                s1 = s1.replace(str1, str1.replace(str2, str3))
            output = re.sub('\.replace\(\s*/([^)]+)/g?, [\'"]([^\'"]*)[\'"]\)', '', s1)
        return output

    def b64decode_str(self, text):
        def cic(expression):
            """
            From 'base64dump.py' by Didier Stevens@https://DidierStevens.com
            """
            if callable(expression):
                return expression()
            else:
                return expression
        def iff(expression, value_true, value_false):
            """
            From 'base64dump.py' by Didier Stevens@https://DidierStevens.com
            """
            if expression:
                return cic(value_true)
            else:
                return cic(value_false)
        def ascii_dump(data):
            """
            From 'base64dump.py' by Didier Stevens@https://DidierStevens.com
            """
            return ''.join([iff(ord(b) >= 32, b, '') for b in data])

        output = None
        b64str = re.findall('((?:[A-Za-z0-9+/]{3,}={0,2}[\r]?[\n]?){6,})', text)
        s1 = text
        for bmatch in b64str:
            s = bmatch.replace('\n', '').replace('\r', '').replace(' ', '')
            uniq_char = ''.join(set(s))
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
                    if len(d) > 500 and sha256hash not in self.hashes:
                        for ft in self.FILETYPES:
                            if (ft in ftype and not 'octet-stream' in ftype) or ft in mag_ftype:
                                b64_file_path = os.path.join(self.wd, "{}_cb_b64_decoded"
                                                             .format(sha256hash[0:10]))
                                with open(b64_file_path, 'wb') as b64_file:
                                    b64_file.write(d)
                                self.files_extracted.add(b64_file_path)
                                self.hashes.add(sha256hash)
                                break
                    if all(ord(c) < 128 for c in d):
                        s1 = s1.replace(bmatch, ascii_dump(d))

        if s1 != text:
            output = s1
        return output

    @staticmethod
    def vars_of_fake_arrays(text):

        output = None
        replacements = re.findall('var\s+([^\s=]+)\s*=\s*\[([^\]]+)\]\[(\d+)\]', text)
        if len(replacements) > 0:
            #    ,- Make sure we do not process these again
            s1 = re.sub(r'var\s+([^=]+)\s*=', r'XXX \1 =', text)
            for varname, array, pos in replacements:
                try:
                    value = re.split('\s*,\s*', array)[int(pos)]
                except IndexError:
                    # print '[' + array + '][' + pos + ']'
                    break
                s1 = s1.replace(varname, value)
            if s1 != text:
                output = s1
        return output

    @staticmethod
    def array_of_strings(text):
        try:
            output = None
            replacements = re.findall('var\s+([^\s=]+)\s*=\s*\[([^\]]+)\]\s*;', text)
            if len(replacements) > 0:
                #    ,- Make sure we do not process these again
                s1 = text
                for varname, values in replacements:
                    occurences = [int(x) for x in re.findall(varname + '\s*\[(\d+)\]', s1)]
                    for i in occurences:
                        try:
                            s1 = re.sub(varname + '\s*\[(%d)\]' % i, values.split(',')[i], s1)
                        except IndexError:
                            # print '[' + array + '][' + pos + ']'
                            break
                if s1 != text:
                    output = s1
        except:
            output = None
        return output

    @staticmethod
    def concat_strings(text):
        output = None
        # Line continuation character in VB -- '_'
        s1 = re.sub('[\'"][\s\n_]*?[+&][\s\n_]*[\'"]', '', text)
        if s1 != text:
            output = s1

        return output

    @staticmethod
    def str_reverse(text):
        output = None
        s1 = text
        # VBA format StrReverse("[text]")
        replacements = re.findall(r'(StrReverse\("(.+?(?="\))))', s1)
        for full, st in replacements:
            reversed_st = full.replace(st, st[::-1]).replace("StrReverse(", "")[:-1]
            s1 = s1.replace(full, reversed_st)
        if s1 != text:
            output = s1
        return output

    @staticmethod
    def powershell_vars(text):
        output = None
        replacements_string = re.findall(r'(\$(?:\w+|{[^\}]+\}))\s*=[^=]\s*[\"\']([^\"\']+)[\"\']', text)
        replacements_func = re.findall(r'(\$(?:\w+|{[^\}]+\}))\s*=\s*([^=\"\'\s\$]{3,50})[\s]', text)
        if len(replacements_string) > 0 or len(replacements_func) > 0:
            #    ,- Make sure we do not process these again
            s1 = re.sub(r'\$((?:\w+|{[^\}]+\}))\s*=', r'\$--\1 =', text)
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
        for full in re.findall(r'"(?:[^"]+[A-Za-z0-9]+\^[A-Za-z0-9]+[^"]+)+"', text):
            output = output.replace(full, full.replace("^", ""))
        if output == text:
            output = None
        return output

    def mswordmacro_vars(self, text):
        try:
            output = text
            # bad, prevent false var replacements like YG="86"
            # Replace regular variables
            replacements = re.findall(r'^\s*((\w+)\s*=\s*((?:["][^"]+["]|[\'][^\']+[\']))[\r]?)$',
                                      output, re.MULTILINE|re.DOTALL)
            if len(replacements) > 0:
                for full, varname, value in replacements:
                    if len(re.findall(r'(\b' + re.escape(varname) + r'\b)', output)) == 1:
                        # If there is only one instance of these, it's probably noise.
                        output = output.replace(full, '<crowbar:mswordmacro_unused_variable_assignment>')
                    else:
                        final_val = value.replace('"', "")
                        # Stacked strings
                        # b = "he"
                        # b = b & "llo "
                        # b = b & "world!"
                        stacked = re.findall(r'^\s*(({0})\s*=\s*({1})\s*[+&]\s*((?:["][^"]+["]|[\'][^\']+[\']))[\r]?)$'
                                             .format(varname, varname), output, re.MULTILINE|re.DOTALL)
                        if len(stacked) > 0:
                            for sfull, varname, varname_b, val in stacked:
                                final_val += val.replace('"', "")
                                output = output.replace(sfull, '<crowbar:mswordmacro_var_assignment>')
                        output = output.replace(full, '<crowbar:mswordmacro_var_assignment>')
                        # If more than a few, assumption is that this did not
                        # work according to plan, so just replace 1 for now.
                        output = re.sub(r'(\b' + re.escape(varname) + r'(?!\s*[+&=])\b)', '"{}"' .format(final_val),
                                        output, count=5)

            # Remaining stacked strings
            replacements = re.findall(r'^\s*((\w+)\s*=\s*(\w+)\s*[+&]\s*((?:["][^"]+["]|[\'][^\']+[\']))[\r]?)$',
                                      output, re.MULTILINE|re.DOTALL)
            vars = set([x[1] for x in replacements])
            for v in vars:
                final_val = ""
                for full, varname, varname_b, value in replacements:
                    if varname != v:
                        continue
                    final_val += value.replace('"', "")
                    output = output.replace(full, '<crowbar:mswordmacro_var_assignment>')
                output = re.sub(r'(\b' + re.escape(v) + r'(?!\s*[+&=])\b)', final_val, output, count=5)

            if output == text:
                output = None

        except:
            output = None
        return output

    def simple_xor_function(self, text):
        output = None
        xorstrings = re.findall('(\w+\("((?:[0-9A-Fa-f][0-9A-Fa-f])+)"\s*,\s*"([^"]+)"\))', text)
        option_a = []
        option_b = []
        s1 = text
        for f, x, k in xorstrings:
            res = self.xor_with_key(x.decode("hex"), k)
            if self.printable_ratio(res) == 1:
                option_a.append((f, x, k, res))
                # print 'A:',f,x,k, res
            else:
                option_a.append((f, x, k, None))
            # try by shifting the key by 1
            res = self.xor_with_key(x.decode("hex"), k[1:] + k[0])
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
                s1 = s1.replace(f, '"' + r + '"')

        if text != s1:
            output = s1
        return output

    @staticmethod
    def xor_with_key(s, k):
        return ''.join([chr(ord(a) ^ ord(b))
                        for a, b in zip(s, (len(s) / len(k) + 1) * k)])

    @staticmethod
    def zp_xor_with_key(s, k):
        return ''.join([a if a == '\0' or a == b else chr(ord(a) ^ ord(b))
                        for a, b in zip(s, (len(s) / len(k) + 1) * k)])

    @staticmethod
    def clean_up_final_layer(text):
        output = re.sub(r'<crowbar:[^>]+>', '', text)
        output = re.sub(r'\n\s*\n', '', output)
        return output

    # --- Main Module --------------------------------------------------------------------------------------------------
    def hammertime(self, max_attempts, raw, before, patterns, wd):
        """
        Main Module.
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
            ('MSWord macro vars', self.mswordmacro_vars),
            ('Powershell vars', self.powershell_vars),
            ('String replace', self.string_replace),
            ('Concat strings', self.concat_strings),
            ('Powershell carets', self.powershell_carets),
            ('Array of strings', self.array_of_strings),
            ('Fake array vars', self.vars_of_fake_arrays),
            ('Reverse strings', self.str_reverse),
            ('CHR and CHRB decode', self.chr_decode),
            ('B64 Decode', self.b64decode_str),
            ('Simple XOR function', self.simple_xor_function),
        ]
        finalpass_tech = [
            ('Charcode', self.charcode),
            ('Charcode hex', self.charcode_hex)
        ]

        idx = 0
        layers_count = 0
        while True:
            if idx > self.max_attempts:
                for name, technique in finalpass_tech:
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
                for name, technique in finalpass_tech:
                    res = technique(layer)
                    if res:
                        layers_list.append((name, res))
                break
            layers_count = len(layers_list)
            idx += 1

        if len(layers_list) > 0:
            final_score = len(layers_list) * 10
            clean = self.clean_up_final_layer(layers_list[-1][1])
            if clean != raw:
                after = set()
                pat_values = patterns.ioc_match(clean, bogon_ip=True, just_network=False)
                for k, val in pat_values.iteritems():
                    if val == "":
                        asc_asc = unicodedata.normalize('NFKC', val).encode('ascii', 'ignore')
                        after.add(asc_asc)
                    else:
                        for v in val:
                            after.add(v)
                diff_tags = after - before
                # Add additional checks to see if the file should be extracted.
                if (len(clean) > 1000 and final_score > 500) or len(diff_tags) > 0 or len(self.files_extracted) > 0:
                    al_res = (ResultSection(SCORE.NULL, "CrowBar Plugin Detected Possible Obfuscated Script:"))
                    mres = (ResultSection(SCORE.NULL, "The following CrowBar modules made deofuscation attempts:",
                                          parent=al_res))
                    mres.score = final_score
                    lcount = Counter([x[0] for x in layers_list])
                    for l, c in lcount.iteritems():
                        mres.add_line("{0}, {1} time(s).".format(l, c))

                    if (len(clean) > 1000 and final_score > 500) or len(diff_tags) > 0:
                        # Display any new IOC tags found
                        if len(pat_values) > 0 and len(diff_tags) > 0:
                            dres = (ResultSection(SCORE.LOW, "IOCs discovered by Crowbar module:",
                                                  body_format=TEXT_FORMAT.MEMORY_DUMP, parent=al_res))
                            for ty, val in pat_values.iteritems():
                                if val == "":
                                    asc_asc = unicodedata.normalize('NFKC', val).encode('ascii', 'ignore')
                                    if asc_asc in diff_tags:
                                        dres.add_line("{} string: {}" .format(ty.replace("_", " "), asc_asc))
                                        al_res.add_tag(TAG_TYPE[ty], asc_asc, TAG_WEIGHT.LOW)
                                else:
                                    for v in val:
                                        if v in diff_tags:
                                            dres.add_line("{} string: {}".format(ty.replace("_", " "), v))
                                            al_res.add_tag(TAG_TYPE[ty], v, TAG_WEIGHT.LOW)

                        # Display final layer
                        lres = (ResultSection(SCORE.NULL, "Final layer:", body_format=TEXT_FORMAT.MEMORY_DUMP,
                                              parent=al_res))

                        lres.add_line("First 500 bytes of file:")
                        lres.add_line(clean[:500])

                    if len(self.files_extracted) > 0:
                        al_res.add_section(ResultSection(SCORE.LOW, "Deobfuscated code of interest extracted in isolation. "
                                                                 "See extracted files."))
                else:
                    clean = None
                    self.files_extracted = None

        return al_res, clean, self.files_extracted
