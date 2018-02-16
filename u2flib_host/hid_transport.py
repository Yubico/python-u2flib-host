# Copyright (c) 2013 Yubico AB
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#    1. Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#    2. Redistributions in binary form must reproduce the above
#       copyright notice, this list of conditions and the following
#       disclaimer in the documentation and/or other materials provided
#       with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

from __future__ import print_function

from .pyu2f import hidtransport
from u2flib_host.device import U2FDevice
from u2flib_host import exc
import six

DEVICES = [
    (0x1050, 0x0200),  # Gnubby
    (0x1050, 0x0113),  # YubiKey NEO U2F
    (0x1050, 0x0114),  # YubiKey NEO OTP+U2F
    (0x1050, 0x0115),  # YubiKey NEO U2F+CCID
    (0x1050, 0x0116),  # YubiKey NEO OTP+U2F+CCID
    (0x1050, 0x0120),  # Security Key by Yubico
    (0x1050, 0x0410),  # YubiKey Plus
    (0x1050, 0x0402),  # YubiKey 4 U2F
    (0x1050, 0x0403),  # YubiKey 4 OTP+U2F
    (0x1050, 0x0406),  # YubiKey 4 U2F+CCID
    (0x1050, 0x0407),  # YubiKey 4 OTP+U2F+CCID
    (0x2581, 0xf1d0),  # Plug-Up U2F Security Key
]
HID_RPT_SIZE = 64

TYPE_INIT = 0x80
U2F_VENDOR_FIRST = 0x40

# USB Commands
CMD_INIT = 0x06
CMD_WINK = 0x08
CMD_PING = 0x01
CMD_APDU = 0x03
CMD_LOCK = 0x04
U2FHID_YUBIKEY_DEVICE_CONFIG = U2F_VENDOR_FIRST

STAT_ERR = 0xbf


def _gen_devices(selector):
    for dev in hidtransport.DiscoverLocalHIDU2FDevices(selector):
        yield HIDDevice(dev)


def list_devices(selector=hidtransport.HidUsageSelector):
    return list(_gen_devices(selector))


class U2FHIDError(Exception):
    def __init__(self, code):
        super(Exception, self).__init__("U2FHIDError: 0x%02x" % code)
        self.code = code


class HIDDevice(U2FDevice):

    """
    U2FDevice implementation using the HID transport.
    """

    def __init__(self, dev):
        self._dev = dev

    def set_mode(self, mode):
        data = mode + b'\x0f\x00\x00'
        self.call(U2FHID_YUBIKEY_DEVICE_CONFIG, data)

    def _do_send_apdu(self, apdu_data):
        return self.call(CMD_APDU, apdu_data)

    def wink(self):
        self.call(CMD_WINK)

    def ping(self, msg=b'Hello U2F'):
        resp = self.call(CMD_PING, msg)
        if resp != msg:
            raise exc.DeviceError("Incorrect PING readback")
        return resp

    def lock(self, lock_time=10):
        self.call(CMD_LOCK, lock_time)

    def call(self, cmd, data=b''):
        if isinstance(data, int):
            data = six.int2byte(data)

        return self._dev.InternalExchange(TYPE_INIT | cmd, data)
