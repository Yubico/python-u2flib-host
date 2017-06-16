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

import os
try:
    import hidraw as hid  # Prefer hidraw
except ImportError:
    import hid
from time import time
from u2flib_host.device import U2FDevice
from u2flib_host.yubicommon.compat import byte2int, int2byte
from u2flib_host import exc

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


def list_devices(dev_class=None):
    dev_class = dev_class or HIDDevice
    devices = []
    for d in hid.enumerate(0, 0):
        usage_page = d['usage_page']
        if usage_page == 0xf1d0 and d['usage'] == 1:
            devices.append(dev_class(d['path']))
        # Usage page doesn't work on Linux
        elif (d['vendor_id'], d['product_id']) in DEVICES:
            device = HIDDevice(d['path'])
            try:
                device.open()
                device.close()
                devices.append(dev_class(d['path']))
            except (exc.DeviceError, IOError, OSError):
                pass
    return devices


def _read_timeout(dev, size, timeout=2.0):
    timeout += time()
    while time() < timeout:
        resp = dev.read(size)
        if resp:
            return resp
    return []


class U2FHIDError(Exception):
    def __init__(self, code):
        super(Exception, self).__init__("U2FHIDError: 0x%02x" % code)
        self.code = code


class HIDDevice(U2FDevice):

    """
    U2FDevice implementation using the HID transport.
    """

    def __init__(self, path):
        self.path = path
        self.cid = b"\xff\xff\xff\xff"

    def open(self):
        self.handle = hid.device()
        self.handle.open_path(self.path)
        self.handle.set_nonblocking(True)
        self.init()

    def close(self):
        if hasattr(self, 'handle'):
            self.handle.close()
            del self.handle

    def init(self):
        nonce = os.urandom(8)
        resp = self.call(CMD_INIT, nonce)
        while resp[:8] != nonce:
            print("Wrong nonce, read again...")
            resp = self._read_resp(self.cid, CMD_INIT)
        self.cid = resp[8:12]

    def set_mode(self, mode):
        data = mode + b"\x0f\x00\x00"
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

    def _send_req(self, cid, cmd, data):
        size = len(data)
        bc_l = int2byte(size & 0xff)
        bc_h = int2byte(size >> 8 & 0xff)
        payload = cid + int2byte(TYPE_INIT | cmd) + bc_h + bc_l + \
            data[:HID_RPT_SIZE - 7]
        payload += b'\0' * (HID_RPT_SIZE - len(payload))
        self.handle.write([0] + [byte2int(c) for c in payload])
        data = data[HID_RPT_SIZE - 7:]
        seq = 0
        while len(data) > 0:
            payload = cid + int2byte(0x7f & seq) + data[:HID_RPT_SIZE - 5]
            payload += b'\0' * (HID_RPT_SIZE - len(payload))
            self.handle.write([0] + [byte2int(c) for c in payload])
            data = data[HID_RPT_SIZE - 5:]
            seq += 1

    def _read_resp(self, cid, cmd):
        resp = b'.'
        header = cid + int2byte(TYPE_INIT | cmd)
        while resp and resp[:5] != header:
            resp_vals = _read_timeout(self.handle, HID_RPT_SIZE)
            resp = b''.join(int2byte(v) for v in resp_vals)
            if resp[:5] == cid + int2byte(STAT_ERR):
                raise U2FHIDError(byte2int(resp[7]))

        if not resp:
            raise exc.DeviceError("Invalid response from device!")

        data_len = (byte2int(resp[5]) << 8) + byte2int(resp[6])
        data = resp[7:min(7 + data_len, HID_RPT_SIZE)]
        data_len -= len(data)

        seq = 0
        while data_len > 0:
            resp_vals = _read_timeout(self.handle, HID_RPT_SIZE)
            resp = b''.join(int2byte(v) for v in resp_vals)
            if resp[:4] != cid:
                raise exc.DeviceError("Wrong CID from device!")
            if byte2int(resp[4]) != seq & 0x7f:
                raise exc.DeviceError("Wrong SEQ from device!")
            seq += 1
            new_data = resp[5:min(5 + data_len, HID_RPT_SIZE)]
            data_len -= len(new_data)
            data += new_data
        return data

    def call(self, cmd, data=b''):
        if isinstance(data, int):
            data = int2byte(data)

        self._send_req(self.cid, cmd, data)
        return self._read_resp(self.cid, cmd)
