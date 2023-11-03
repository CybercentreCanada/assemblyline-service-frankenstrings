# Copyright (C) 2017 FireEye, Inc. All Rights Reserved.
#    Extracted code from FireEye Flare-Floss source code found here
#    http://github.com/fireeye/flare-floss

# Ported to python 3

import re
from collections import namedtuple

ASCII_BYTE = rb" !\"#\$%&\'\(\)\*\+,-\./0123456789:;<=>\?@ABCDEFGHIJKLMNOPQRSTUVWXYZ\[\]\^_`abcdefghijklmnopqrstuvwxyz\{\|\}\\\~\t"
ASCII_RE_4 = re.compile(b"([%s]{%d,})" % (ASCII_BYTE, 4))
UNICODE_RE_4 = re.compile(b"((?:[%s]\x00){%d,})" % (ASCII_BYTE, 4))
REPEATS = [b"A", b"\x00", b"\xfe", b"\xff"]
SLICE_SIZE = 4096

String = namedtuple("String", ["s", "offset"])


def buf_filled_with(buf, character):
    dupe_chunk = character * SLICE_SIZE
    for offset in range(0, len(buf), SLICE_SIZE):
        new_chunk = buf[offset: offset + SLICE_SIZE]
        if dupe_chunk[:len(new_chunk)] != new_chunk:
            return False
    return True


def extract_ascii_strings(buf, n=4):
    '''
    Extract ASCII strings from the given binary data.
    :param buf: A bytestring.
    :type buf: bytes
    :param n: The minimum length of strings to extract.
    :type n: int
    :rtype: Sequence[bytes]
    '''

    if not buf:
        return

    if (buf[0] in REPEATS) and buf_filled_with(buf, buf[0]):
        return

    r = None
    if n == 4:
        r = ASCII_RE_4
    else:
        reg = b"([%s]{%d,})" % (ASCII_BYTE, n)
        r = re.compile(reg)
    for match in r.finditer(buf):
        yield String(match.group(), match.start())


def extract_unicode_strings(buf, n=4):
    '''
    Extract naive UTF-16 strings from the given binary data.
    :param buf: A bytestring.
    :type buf: bytes
    :param n: The minimum length of strings to extract.
    :type n: int
    :rtype: Sequence[bytes]
    '''

    if not buf:
        return

    if (buf[0] in REPEATS) and buf_filled_with(buf, buf[0]):
        return

    if n == 4:
        r = UNICODE_RE_4
    else:
        reg = b"((?:[%s]\x00){%d,})" % (ASCII_BYTE, n)
        r = re.compile(reg)
    for match in r.finditer(buf):
        try:
            yield String(match.group().decode("utf-16").encode("utf-8"), match.start())
        except UnicodeDecodeError:
            pass


def main():
    import sys

    with open(sys.argv[1], 'rb') as f:
        b = f.read()

    for s in extract_ascii_strings(b):
        print('0x{:x}: {:s}'.format(s.offset, s.s.decode('utf-8')))

    for s in extract_unicode_strings(b):
        print('0x{:x}: {:s}'.format(s.offset, s.s.decode('utf-8')))


if __name__ == '__main__':
    main()
