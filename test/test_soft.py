
import os
import base64
import struct
import tempfile
import unittest

from u2flib_host.soft import SoftU2FDevice
from u2flib_host.constants import INS_ENROLL, INS_SIGN

CLIENT_PARAM = b'clientABCDEFGHIJKLMNOPQRSTUVWXYZ' # 32 bytes
APP_PARAM =    b'test_SoftU2FDevice0123456789ABCD' # 32 bytes

class TestSoftU2FDevice(unittest.TestCase):
    def setUp(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b'{"counter": 0, "keys": {}}')
            self.device_path = f.name

    def tearDown(self):
        os.unlink(self.device_path)

    def test_init(self):
        dev = SoftU2FDevice(self.device_path)
        self.assertEqual(dev.data['counter'], 0)
        self.assertEqual(dev.data['keys'], {})

    def test_get_supported_versions(self):
        dev = SoftU2FDevice(self.device_path)
        self.assertEqual(dev.get_supported_versions(), ['U2F_V2'])

    def test_registeration(self):
        dev = SoftU2FDevice(self.device_path)
        request = struct.pack('32s 32s', CLIENT_PARAM, APP_PARAM)
        response = dev.send_apdu(INS_ENROLL, data=request)
        self.assertEqual(dev.data['counter'], 0)
        self.assertTrue(len(dev.data['keys']), 1)

        pub_key, key_handle_len, key_handle, cert, signature = struct.unpack('x 65s B 64s %is 32s' % (len(response)-(1+65+1+64+32),), response)
        self.assertEqual(len(key_handle), key_handle_len)
        kh_hex = base64.b16encode(key_handle).decode('ascii')
        self.assertIn(kh_hex, dev.data['keys'])
        self.assertEqual(base64.b16decode(dev.data['keys'][kh_hex]['app_param']), APP_PARAM)
        self.assertEqual(dev.data['keys'][kh_hex]['priv_key'].split('\n')[0],
                         '-----BEGIN PRIVATE KEY-----')

        request = struct.pack('32s 32s B %is' % key_handle_len,
                              CLIENT_PARAM, APP_PARAM, key_handle_len, key_handle)
        response = dev.send_apdu(INS_SIGN, data=request)
        self.assertEqual(dev.data['counter'], 1)

        touch, counter, signature = struct.unpack('>? I %is' % (len(response)-(1+4),), response)
        self.assertTrue(touch)
        self.assertEqual(counter, 1)

