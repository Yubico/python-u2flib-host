#    Copyright (C) 2014  Yubico AB
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.

import os
from u2flib_host.device import U2FDevice
from u2flib_host import exc

VENDOR_ID = 0x1050
PRODUCT_ID = 0x0211
INTERFACE = 0
ENDPOINT_OUT = 0x1
ENDPOINT_IN = 0x81

# USB Commands
CMD_WINK = 0x88
CMD_PROMPT = 0x87
CMD_APDU = 0x83
CMD_SYNC = 0xbc

TIMEOUT = 1000
BUF_SIZE = 2048


def list_devices():
    # Once standardized, this should be VID/PID-agnostic
    try:
        # libusbx on Windows doesn't like using usb.busses(), so check if we
        # have PyUSB <= 1.0 and can avoid it
        import usb.core
        import usb.legacy
        return [WinUSBDevice(usb.legacy.Device(d)) for d in usb.core.find(
            find_all=True, idVendor=VENDOR_ID, idProduct=PRODUCT_ID)]
    except ImportError:
        # Fallback to PyUSB 0.4
        import usb
        return [WinUSBDevice(dev) for b in usb.busses() for dev in b.devices
                if dev.idVendor == VENDOR_ID and dev.idProduct == PRODUCT_ID]


class WinUSBDevice(U2FDevice):

    """
    U2FDevice implementation using the WinUSB transport.
    """

    def __init__(self, device):
        self.device = device

    def open(self):
        self.handle = self.device.open()
        self.handle.claimInterface(INTERFACE)

    def close(self):
        if hasattr(self, 'handle'):
            self.handle.releaseInterface()
            del self.handle

    def _do_send_apdu(self, apdu_data):
        return self.call(CMD_APDU, apdu_data)

    def prompt(self, seconds):
        self.call(CMD_PROMPT, seconds)

    def call(self, cmd, data=''):
        if isinstance(data, int):
            data = chr(data)
        size = len(data)
        bc_l = chr(size & 0xff)
        bc_h = chr(size >> 8 & 0xff)
        payload = os.urandom(4) + chr(cmd) + bc_h + bc_l + data
        self.handle.bulkWrite(ENDPOINT_OUT, payload, TIMEOUT)
        resp = bytearray(self.handle.bulkRead(ENDPOINT_IN, BUF_SIZE, TIMEOUT))
        header = str(resp[:5])
        if header != payload[:5]:
            raise exc.DeviceError("Invalid response from device!")
        data = str(resp[7:])
        data_len = (resp[5] << 8) + resp[6]
        if len(data) != data_len:
            raise exc.DeviceError("Invalid response size!")
        return data
