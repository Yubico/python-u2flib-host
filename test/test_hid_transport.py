import os
import unittest
from u2flib_host import hid_transport
from u2flib_host import exc
from u2flib_host.yubicommon.compat import byte2int, int2byte

try:
    from unittest.mock import patch
except ImportError:
    from mock import patch

class TestHIDDevice(object):
    def write(self, payload):
        self.cid = payload[1:5]
        self.cmd = payload[5] ^ hid_transport.TYPE_INIT
        self.size = (payload[6] << 8) + payload[7]
        self.data = list(map(int2byte, payload[8:(8 + self.size)]))

    def read(self, size):
        self.response += [0] * (hid_transport.HID_RPT_SIZE - len(self.response) + 1)
        types = list(map(type, self.response))
        return self.response

    def close(self):
        return None


class HIDDeviceTest(unittest.TestCase):
    @classmethod
    def build_response(cls, cid, cmd, data):
        size = len(data)
        size_low = size & 0xff
        size_high = (size >> 8) & 0xff
        response = list(map(byte2int, cid)) + list(map(byte2int, cmd)) + [size_high, size_low]
        response += list(map(byte2int, data))
        return response


    def test_init(self):
        with patch.object(os, 'urandom', return_value=(b'\xab'*8)) as mock_method:
            hid_device = TestHIDDevice()
            hid_device.response = HIDDeviceTest.build_response(
                b'\xff'*4,
                b'\x86',
                b'\xab'*8 + b'\x01\x02\x03\x04' + b'\x01\x02\x03\x04\x05'
            )

            dev = hid_transport.HIDDevice('/dev/null')
            dev.handle = hid_device
            dev.init()
            self.assertEqual(dev.capabilities, 0x05)

    def test_init_invalid_nonce(self):
        with patch.object(os, 'urandom', return_value=(b'\xab'*8)) as mock_method:
            hid_device = TestHIDDevice()
            hid_device.response = HIDDeviceTest.build_response(
                b'\xff'*4,
                b'\x86',
                b'\x00'*8 + b'\x01\x02\x03\x04' + b'\x01\x02\x03\x04\x05'
            )

            dev = hid_transport.HIDDevice('/dev/null')
            dev.handle = hid_device
            with self.assertRaises(exc.DeviceError) as context:
                dev.init()
                self.assertTrue('Wrong INIT response from device' in context.exception)

    def test_init_invalid_length(self):
        with patch.object(os, 'urandom', return_value=(b'\xab'*8)) as mock_method:
            hid_device = TestHIDDevice()
            hid_device.response = HIDDeviceTest.build_response(
                b'\xff'*4,
                b'\x86',
                b'\xab'*8 + b'\x01\x02\x03\x04' + b'\x01\x02\x03\x04'
            )

            dev = hid_transport.HIDDevice('/dev/null')
            dev.handle = hid_device

            with self.assertRaises(exc.DeviceError) as context:
                dev.init()
                self.assertTrue('Wrong INIT response from device' in context.exception)

    def test_ctap2_enabled(self):
        dev = hid_transport.HIDDevice('/dev/null')
        dev.capabilities = 0x01
        self.assertFalse(dev.ctap2_enabled())
        dev.capabilities = 0x04
        self.assertTrue(dev.ctap2_enabled())
