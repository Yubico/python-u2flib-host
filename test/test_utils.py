# coding=utf-8

from u2flib_host.utils import (
    u2str,
    websafe_encode,
    websafe_decode,
    H,
)


def test_u2str():
    data1 = {
        u'greeting_en': u'Hello world',
        u'greeting_se': u'Hallå världen',
        u'recursive': {
            'plaintext': [u'foo', 'bar', u'BΛZ'],
        },
    }
    assert u2str(data1) == {
        'greeting_en': 'Hello world',
        'greeting_se': 'Hall\xc3\xa5 v\xc3\xa4rlden', # utf-8 encoded
        'recursive': {
            'plaintext': ['foo', 'bar', 'B\xce\x9bZ'],
        },
    }


def test_websafe_decode():
   # Base64 vectors adapted from https://tools.ietf.org/html/rfc4648#section-10
   assert websafe_decode('') == ''
   assert websafe_decode('Zg') == 'f'
   assert websafe_decode('Zm8') == 'fo'
   assert websafe_decode('Zm9v') == 'foo'
   assert websafe_decode('Zm9vYg') == 'foob'
   assert websafe_decode('Zm9vYmE') == 'fooba'
   assert websafe_decode('Zm9vYmFy') == 'foobar'


def test_websafe_encode():
   # Base64 vectors adapted from https://tools.ietf.org/html/rfc4648#section-10
   assert websafe_encode('') == ''
   assert websafe_encode('f') == 'Zg'
   assert websafe_encode('fo') == 'Zm8'
   assert websafe_encode('foo') == 'Zm9v'
   assert websafe_encode('foob') == 'Zm9vYg'
   assert websafe_encode('fooba') == 'Zm9vYmE'
   assert websafe_encode('foobar') == 'Zm9vYmFy'



def test_H():
    # SHA-256 vectors adapted from http://www.nsrl.nist.gov/testdata/
    assert H('abc') == '\xbax\x16\xbf\x8f\x01\xcf\xeaAA@\xde]\xae"#\xb0' \
                       '\x03a\xa3\x96\x17z\x9c\xb4\x10\xffa\xf2\x00\x15\xad'

