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
import hid
from time import time
from u2flib_host.device import U2FDevice
from u2flib_host import exc

VENDOR_ID = 0x1050
PRODUCT_ID = 0x0200
HID_RPT_SIZE = 64

TYPE_INIT = 0x80

# USB Commands
CMD_WINK = 0x08
CMD_PROMPT = 0x07
CMD_APDU = 0x03
CMD_SYNC = 0xbc

STAT_ERR = 0xbf

TIMEOUT = 1000


def list_devices():
    # Once standardized, this should be VID/PID-agnostic
    devices = []
    for d in hid.enumerate(0, 0):
        if d['vendor_id'] == VENDOR_ID and d['product_id'] == PRODUCT_ID:
            devices.append(HIDDevice(d['path']))
    return devices


def _read_timeout(dev, size, timeout=1.0):
    timeout += time()
    while time() < timeout:
        resp = dev.read(size)
        if resp:
            return resp
    return []


class SyncError(Exception):
    pass


class HIDDevice(U2FDevice):

    """
    U2FDevice implementation using the HID transport.
    """

    def __init__(self, path):
        self.path = path

    def open(self):
        self.handle = hid.device()
        self.handle.open_path(self.path)
        self.handle.set_nonblocking(True)

    def close(self):
        if hasattr(self, 'handle'):
            self.handle.close()
            del self.handle

    def _do_send_apdu(self, apdu_data):
        return self.call(CMD_APDU, apdu_data)

    def sync(self):
        self.call(CMD_SYNC)

    def prompt(self, seconds):
        self.call(CMD_PROMPT, seconds)

    def wink(self):
        self.call(CMD_WINK)

    def _send_req(self, cid, cmd, data):
        size = len(data)
        bc_l = chr(size & 0xff)
        bc_h = chr(size >> 8 & 0xff)
        payload = cid + chr(TYPE_INIT | cmd) + bc_h + bc_l + \
            data[:HID_RPT_SIZE - 7]
        payload += '\0' * (HID_RPT_SIZE - len(payload))
        self.handle.write([0] + map(ord, payload))
        data = data[HID_RPT_SIZE - 7:]
        seq = 0
        while len(data) > 0:
            payload = cid + chr(0x7f & seq) + data[:HID_RPT_SIZE - 5]
            payload += '\0' * (HID_RPT_SIZE - len(payload))
            self.handle.write([0] + map(ord, payload))
            data = data[HID_RPT_SIZE - 5:]
            seq += 1

    def _read_resp(self, cid, cmd):
        resp = '.'
        header = cid + chr(TYPE_INIT | cmd)
        while resp and resp[:5] != header:
            resp = ''.join(map(chr, _read_timeout(self.handle, HID_RPT_SIZE)))
            if resp[:5] == cid + chr(STAT_ERR):
                raise SyncError()

        if not resp:
            raise exc.DeviceError("Invalid response from device!")

        data_len = (ord(resp[5]) << 8) + ord(resp[6])
        data = resp[7:min(7 + data_len, HID_RPT_SIZE)]
        data_len -= len(data)

        seq = 0
        while data_len > 0:
            resp = ''.join(map(chr, _read_timeout(self.handle, HID_RPT_SIZE)))
            if resp[:4] != cid:
                raise exc.DeviceError("Wrong CID from device!")
            if ord(resp[4]) != seq & 0x7f:
                raise exc.DeviceError("Wrong SEQ from device!")
            seq += 1
            new_data = resp[5:min(5 + data_len, HID_RPT_SIZE)]
            data_len -= len(new_data)
            data += new_data
        return data

    def call(self, cmd, data=''):
        cid = os.urandom(4)
        if isinstance(data, int):
            data = chr(data)

        self._send_req(cid, cmd, data)
        try:
            resp = self._read_resp(cid, cmd)
        except SyncError:
            self.sync()
            return self.call(cmd, data)

        return resp
