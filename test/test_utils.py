# coding=utf-8

import unittest

from u2flib_host.utils import (
    u2str,
    websafe_encode,
    websafe_decode,
    H,
)


class TestU2Str(unittest.TestCase):
    def test_u2str(self):
        data1 = {
            u'greeting_en': u'Hello world',
            u'greeting_se': u'Hallå världen',
            u'recursive': {
                'plaintext': [u'foo', 'bar', u'BΛZ'],
            },
        }
        self.assertEqual(u2str(data1), {
            'greeting_en': 'Hello world',
            'greeting_se': 'Hall\xc3\xa5 v\xc3\xa4rlden', # utf-8 encoded
            'recursive': {
                'plaintext': ['foo', 'bar', 'B\xce\x9bZ'],
            },
        })


class TestWebSafe(unittest.TestCase):
    # Base64 vectors adapted from https://tools.ietf.org/html/rfc4648#section-10

    def test_websafe_decode(self):
       self.assertEqual(websafe_decode(''), '')
       self.assertEqual(websafe_decode('Zg'), 'f')
       self.assertEqual(websafe_decode('Zm8'), 'fo')
       self.assertEqual(websafe_decode('Zm9v'), 'foo')
       self.assertEqual(websafe_decode('Zm9vYg'), 'foob')
       self.assertEqual(websafe_decode('Zm9vYmE'), 'fooba')
       self.assertEqual(websafe_decode('Zm9vYmFy'), 'foobar')

    def test_websafe_encode(self):
       self.assertEqual(websafe_encode(''), '')
       self.assertEqual(websafe_encode('f'), 'Zg')
       self.assertEqual(websafe_encode('fo'), 'Zm8')
       self.assertEqual(websafe_encode('foo'), 'Zm9v')
       self.assertEqual(websafe_encode('foob'), 'Zm9vYg')
       self.assertEqual(websafe_encode('fooba'), 'Zm9vYmE')
       self.assertEqual(websafe_encode('foobar'), 'Zm9vYmFy')


class TestH(unittest.TestCase):
    # SHA-256 vectors adapted from http://www.nsrl.nist.gov/testdata/

    def test_H(self):
        self.assertEqual(H('abc'),
            '\xbax\x16\xbf\x8f\x01\xcf\xeaAA@\xde]\xae"#\xb0'
            '\x03a\xa3\x96\x17z\x9c\xb4\x10\xffa\xf2\x00\x15\xad'
        )

