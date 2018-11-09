from al_services.alsvc_frankenstrings.balbuzard.patterns import PatternMatch
from assemblyline.al.common.result import ResultSection, SCORE, TAG_TYPE, TAG_WEIGHT, TEXT_FORMAT
from collections import Counter
import binascii
import re
import unicodedata


class CrowBar(object):

    def __init__(self):

        self.validchars = \
            ' 0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~'
        self.binchars = ''.join([c for c in map(chr, range(0, 256)) if c not in self.validchars])
        self.max_attempts = None

    # --- Support Modules ----------------------------------------------------------------------------------------------

    def printable_ratio(self, text):
        return float(float(len(text.translate(None, self.binchars))) / float(len(text)))

    @staticmethod
    def add1b(s, k):
        return ''.join([chr((ord(c) + k) & 0xff) for c in s])

    def charcode(self, text):
        final = False
        output = None
        arrayofints = filter(lambda n: n < 256,
                             map(int, re.findall('(\d+)', str(re.findall('\D{1,2}\d{2,3}', text)))))
        if len(arrayofints) > 20:
            s1 = ''.join(map(chr, arrayofints))
            if self.printable_ratio(s1) > .75 and (float(len(s1)) / float(len(text))) > .10:
                # if the output is mostly readable and big enough
                output = s1

        return final, output

    def charcode_hex(self, text):

        final = False
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

        return final, output

    @staticmethod
    def string_replace(text):
        final = False
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
                                             s2):
                    # Execute the substitution
                    s2 = s2.replace(str1, str2)
                # Remove the replace calls from the layer (prevent accidental substitutions in the next step)
                s2 = s2[:s2.index('.replace(')]
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
        return final, output

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

        final = False
        output = None
        b64str = re.findall('([\x20](?:[A-Za-z0-9+/]{3,}={0,2}[\r]?[\n]?){6,})', text)
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
                    if all(ord(c) < 128 for c in d):
                        s1 = s1.replace(s, ascii_dump(d))

        if s1 != text:
            output = s1
        return final, output

    @staticmethod
    def vars_of_fake_arrays(text):
        final = False
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
                    raise
                s1 = s1.replace(varname, value)
            if s1 != text:
                output = s1
        return final, output

    @staticmethod
    def array_of_strings(text):
        try:
            final = False
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
                            raise
                if s1 != text:
                    output = s1
        except:
            final = False
            output = None
        return final, output

    @staticmethod
    def concat_strings(text):
        final = False
        output = None
        # Line continuation character in VB -- '_'
        s1 = re.sub('[\'"][\s\n_]*?[+&][\s\n_]*[\'"]', '', text)
        if s1 != text:
            output = s1

        return final, output

    @staticmethod
    def str_reverse(text):
        final = False
        output = None
        s1 = text
        # VBA format StrReverse("[text]")
        replacements = re.findall(r'(StrReverse\("(.+?(?="\))))', s1)
        for full, st in replacements:
            reversed_st = full.replace(st, st[::-1]).replace("StrReverse(", "")[:-1]
            s1 = s1.replace(full, reversed_st)
        if s1 != text:
            output = s1
        return final, output

    @staticmethod
    def powershell_vars(text):
        final = False
        output = None
        replacements_string = re.findall(r'(\$\w+)\s*=[^=]\s*[\"\']([^\"\']+)[\"\']', text)
        replacements_func = re.findall(r'(\$\w+)\s*=\s*([^=\"\'\s]{3,50})[\s]', text)
        if len(replacements_string) > 0 or len(replacements_func) > 0:
            #    ,- Make sure we do not process these again
            s1 = re.sub(r'[^_](\$\w+)\s*=', r'_\1 =', text)
            for varname, string in replacements_string:
                s1 = s1.replace(varname, string)
            for varname, string in replacements_func:
                s1 = s1.replace(varname, string)
            if output != text:
                output = s1

        return final, output

    @staticmethod
    def powershell_carets(text):
        final = False
        output = text
        for full in re.findall(r'"(?:[^"]+[A-Za-z0-9]+\^[A-Za-z0-9]+[^"]+)+"', text):
            output = output.replace(full, full.replace("^", ""))
        if output == text:
            output = None
        return final, output

    def mswordmacro_vars(self, text):
        try:
            final = False
            output = text
            # bad, prevent false var replacements like YG="86"
            # Replace regular variables
            replacements = re.findall(r'^((\w+)\s*=\s*(["\'][^"\']+["\'])[\r]?)$', output, re.M)
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
                        stacked = re.findall(r'^(({0})\s*=\s*({1})\s*&\s*(["\'][^"\']+["\'])[\r]?)$'
                                             .format(varname, varname), output, re.M)
                        if len(stacked) > 0:
                            for sfull, varname, varname_b, val in stacked:
                                final_val += val.replace('"', "")
                                output = output.replace(sfull, '<crowbar:mswordmacro_var_assignment>')
                        output = output.replace(full, '<crowbar:mswordmacro_var_assignment>')
                        output = re.sub(r'(\b' + re.escape(varname) + r'\b)', '"{}"' .format(final_val), output)

            # Remaining stacked strings
            replacements = re.findall(r'^((\w+)\s*=\s*(\w+)\s*&\s*(["\'][^"\']+["\'])[\r]?)$',
                                      output, re.M)
            vars = set([x[1] for x in replacements])
            for v in vars:
                final_val = ""
                for full, varname, varname_b, value in replacements:
                    if varname != v:
                        continue
                    final_val += value.replace('"', "")
                    output = output.replace(full, '<crowbar:mswordmacro_var_assignment>')
                output = re.sub(r'(\b' + re.escape(v) + r'\b)', final_val, output)

            if output == text:
                output = None

        except:
            final = False
            output = None
        return final, output

    def simple_xor_function(self, text):
        final = False
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
        return final, output

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
    def hammertime(self, max_attempts, raw, before):
        """
        Main Module.
        """
        patterns = PatternMatch()
        self.max_attempts = max_attempts
        layers_list = []
        layer = raw
        techniques = [
            ('Concat strings', self.concat_strings, False),
            ('MSWord macro vars', self.mswordmacro_vars, False),
            ('Powershell vars', self.powershell_vars, False),
            ('String replace', self.string_replace, False),
            ('Powershell carets', self.powershell_carets, False),
            ('Array of strings', self.array_of_strings, False),
            ('Fake array vars', self.vars_of_fake_arrays, False),
            ('Reverse strings', self.str_reverse, False),
            ('B64 Decode', self.b64decode_str, True),
            ('Simple XOR function', self.simple_xor_function, False),
            ('Charcode', self.charcode, False),
            ('Charcode hex', self.charcode_hex, False)
        ]
        extract_file = False
        done = False
        idx = 0
        while not done:
            if idx > self.max_attempts:
                break
            done = True
            for name, technique, extract in techniques:
                final, res = technique(layer)
                if res:
                    layers_list.append((name, res))
                    if extract:
                        extract_file = True
                    # Looks like it worked, restart with new layer
                    layer = res
                    done = final
                    if done:
                        break
            idx += 1

        if len(layers_list) > 0:
            final_score = len(layers_list) * 10
            clean = self.clean_up_final_layer(layers_list[-1][1])
            if clean != raw:
                after = []
                pat_values = patterns.ioc_match(clean, bogon_ip=True, just_network=False)
                for k, val in pat_values.iteritems():
                    if val == "":
                        asc_asc = unicodedata.normalize('NFKC', val).encode('ascii', 'ignore')
                        after.append(asc_asc)
                    else:
                        for v in val:
                            after.append(v)
                diff_tags = list(set(before).symmetric_difference(set(after)))
                # Add additional checks to see if the file should be extracted.
                if (len(clean) > 1000 and final_score > 500) or (len(before) < len(after)) or extract_file:
                    res = (ResultSection(SCORE.NULL, "CrowBar Plugin Detected Possible Obfuscated Script:"))
                    mres = (ResultSection(SCORE.NULL, "The following CrowBar modules made deofuscation attempts:",
                                          parent=res))
                    mres.score = final_score
                    lcount = Counter([x[0] for x in layers_list])
                    for l, c in lcount.iteritems():
                        mres.add_line("{0}, {1} time(s).".format(l, c))

                    # Display final layer
                    lres = (ResultSection(SCORE.NULL, "Final layer:", body_format=TEXT_FORMAT.MEMORY_DUMP,
                                          parent=res))

                    lres.add_line("First 500 bytes of file:")
                    lres.add_line(clean[:500])

                    if len(pat_values) > 0 and len(diff_tags) > 0:
                        for ty, val in pat_values.iteritems():
                            if val == "":
                                asc_asc = unicodedata.normalize('NFKC', val).encode('ascii', 'ignore')
                                if asc_asc in diff_tags:
                                    res.add_tag(TAG_TYPE[ty], asc_asc, TAG_WEIGHT.LOW)
                            else:
                                for v in val:
                                    if v in diff_tags:
                                        res.add_tag(TAG_TYPE[ty], v, TAG_WEIGHT.LOW)
                    return res, clean

        return None, None
