
import unittest

from u2flib_host import exc


class APDUErrorTest(unittest.TestCase):
    def test_init(self):
        error = exc.APDUError(0x3039)
        self.assertEqual(error.args[0], '0x3039')
        self.assertEqual(error.code, 0x3039)
        self.assertEqual(error.sw1, 0x30)
        self.assertEqual(error.sw2, 0x39)
