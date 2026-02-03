import io
import pytest

from resolver.protocol import encode_domain_name, decode_domain_name

# Encoder tests:
def test_successful_encode():
    domain = 'www.test.com'
    expected_bytes = b'\x03www\x04test\x03com\x00'
    expected_hex = '03 77 77 77 04 74 65 73 74 03 63 6f 6d 00'

    assert encode_domain_name(domain) == expected_bytes
    assert encode_domain_name(domain).hex(' ') == expected_hex

@pytest.mark.parametrize("invalid_input", [
    'www..test.com',
    '',
    'www.test.com' * 30
])
def test_failed_encode(invalid_input):
    with pytest.raises(ValueError):
        encode_domain_name(invalid_input)

# Decoder tests:
def test_successful_decode():
    buffered_domain = b'\x03www\x04test\x03com\x00'
    buffer = io.BytesIO(buffered_domain)
    expected = 'www.test.com'

    assert decode_domain_name(buffer) == expected

def test_compressed_decode():
    compressed_domain = b'\x03www\x04test\x03com\x00\x03api\xc0\x04\xff\xff\x00'
    buffer = io.BytesIO(compressed_domain)
    buffer.seek(14)
    expected = 'api.test.com'

    assert decode_domain_name(buffer) == expected

def test_compression_loop_decode():
    malicious_domain = b'\xc0\x00'
    buffer = io.BytesIO(malicious_domain)
    
    with pytest.raises(ValueError):
        decode_domain_name(buffer)

def test_empty_decode():
    empty_domain = b'\x00'
    buffer = io.BytesIO(empty_domain)
    expected = ''

    assert decode_domain_name(buffer) == expected

def test_single_label_decode():
    single_label_domain = b'\x03www\x00'
    buffer = io.BytesIO(single_label_domain)
    expected = 'www'

    assert decode_domain_name(buffer) == expected