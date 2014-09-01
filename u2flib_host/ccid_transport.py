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

import re
from smartcard.System import readers
from u2flib_host.device import U2FDevice

AID = 'a0000005271002'
CARD_PATTERN = re.compile(".*Yubikey NEO.*")


def hex2cmd(data):
    return map(ord, data.decode('hex'))


def list_devices():
    devices = []
    for reader in readers():
        if CARD_PATTERN.match(reader.name):
            conn = reader.createConnection()
            try:
                conn.connect()
                data, sw1, sw2 = conn.transmit(hex2cmd('00a4040007%s' % AID))
                if (sw1, sw2) == (0x90, 0x00):
                    devices.append(CCIDDevice(conn))
            except:
                pass
    return devices


class CCIDDevice(U2FDevice):
    def __init__(self, conn):
        self.conn = conn

    def _do_send_apdu(self, apdu_data):
        data, sw1, sw2 = self.conn.transmit(map(ord, apdu_data))
        return ''.join(map(chr, data)) + chr(sw1) + chr(sw2)
