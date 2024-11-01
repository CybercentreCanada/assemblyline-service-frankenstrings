import pytest

from frankenstrings.frankenstrings import extract_pdf_content

@pytest.mark.parametrize(
    ('data', 'expected'),
    [
        (b'', b''),
        (b'%PDF-1.7\nthis is a normal pdf file', b''),
        (b'%%%%%%%%%%%%PDF-1.7\n This is still pdf', b'%PDF-1.7\n This is still pdf'),
        (b'a'*1024 + b'%PDF-1.7\n This is too late to be pdf', b''),
        (b'a'*1023 + b'%PDF-1.7\n But this pdf is fine', b'%PDF-1.7\n But this pdf is fine'),
    ]
)
def test_extract_pdf_content(data: bytes, expected: bytes) -> None:
    assert extract_pdf_content(data) == expected
