import io
import pytest

from resolver.protocol import encode_domain_name, decode_domain_name, DNSHeaderFlags, DNSHeader, DNSQuestion

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

# DNSHeaderFlags tests:
@pytest.mark.parametrize('qr,opcode,rcode,expected', [
    (1, 0, 0, 0x8000),
    (0, 4, 0, 0x2000),
    (0, 0, 3, 0x0003),
])
def test_valid_flag_pack(qr, opcode, rcode, expected):
    f = DNSHeaderFlags(qr=qr, opcode=opcode, rcode=rcode)
    assert f.pack_flags() == expected

@pytest.mark.parametrize('raw_int,expected', [
    (0x8000, DNSHeaderFlags(qr=1, opcode=0, rcode=0)),
    (0x2000, DNSHeaderFlags(qr=0, opcode=4, rcode=0)),
    (0x0003, DNSHeaderFlags(qr=0, opcode=0, rcode=3))
])
def test_valid_flag_unpack(raw_int, expected):
    assert DNSHeaderFlags.unpack_flags(raw_int=raw_int) == expected # __eq__ is supported because DNSHeaderFlags is a dataclass

# DNSHeader tests:
def test_valid_header_to_bytes():
    flags_input = DNSHeaderFlags(qr=0, opcode=0, aa=0, tc=0, rd=1, ra=0, z=0, rcode=0)
    header = DNSHeader(
        id=0x1234, 
        flags=flags_input, 
        qd_count=1, 
        an_count=0, 
        ns_count=0, 
        ar_count=0
    )
    expected_output = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'

    assert header.to_bytes() == expected_output

def test_valid_header_from_bytes():
    input = b'\xaa\xaa\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00'
    buffer = io.BytesIO(input)

    expected_flags = DNSHeaderFlags(qr=1, opcode=0, aa=0, tc=0, rd=1, ra=1, z=0, rcode=0)
    expected = DNSHeader(
        id=0xAAAA, 
        flags=expected_flags, 
        qd_count=1, 
        an_count=1, 
        ns_count=0, 
        ar_count=0
    )

    assert DNSHeader.from_bytes(buffer) == expected

def test_valid_long_header_from_bytes():
    # this input has extraneous bytes at the end that should not be parsed
    input = b'\xaa\xaa\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x01\x00\x01\x00'
    buffer = io.BytesIO(input)

    expected_flags = DNSHeaderFlags(qr=1, opcode=0, aa=0, tc=0, rd=1, ra=1, z=0, rcode=0)
    expected = DNSHeader(
        id=0xAAAA, 
        flags=expected_flags, 
        qd_count=1, 
        an_count=1, 
        ns_count=0, 
        ar_count=0
    )

    assert DNSHeader.from_bytes(buffer) == expected

# DNSQuestion test:
def test_valid_question_to_bytes():
    question = DNSQuestion('www.google.com', 1, 1)
    expected = b'\x03www\x06google\x03com\x00\x00\x01\x00\x01'

    assert question.to_bytes() == expected

def test_valid_question_from_bytes():
    input = b'\x03www\x06google\x03com\x00\x00\x01\x00\x01'
    buffer = io.BytesIO(input)

    expected = DNSQuestion(qname='www.google.com', qtype=1, qclass=1)

    assert DNSQuestion.from_bytes(buffer) == expected

def test_valid_long_question_from_bytes():
    # this input has extraneous bytes at the end that should not be parsed
    input = b'\x03www\x06google\x03com\x00\x00\x01\x00\x01\x01\x00\x01'
    buffer = io.BytesIO(input)

    expected = DNSQuestion(qname='www.google.com', qtype=1, qclass=1)

    assert DNSQuestion.from_bytes(buffer) == expected