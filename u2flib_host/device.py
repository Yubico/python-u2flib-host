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

from u2flib_host.constants import APDU_OK
from u2flib_host import exc
import sys

INS_GET_VERSION = 0x03


class U2FDevice(object):

    """
    A handle to a U2F device.
    device.open() needs to be called prior to using the device, and
    device.close() should be called when the device is no longer needed, to
    ensure that any held resources are released.
    As an aternative, the 'with' statement can be used:

        with device as dev:
            dev.send_apdu(...)
    """

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, type, value, traceback):
        self.close()

    def __del__(self):
        self.close()

    def open(self):
        """
        Opens the device for use.
        """
        pass

    def close(self):
        """
        Closes the device, making it available for use by others.
        """
        pass

    def get_supported_versions(self):
        """
        Gets a list of supported U2F versions from the device.
        """
        if not hasattr(self, '_versions'):
            try:
                self._versions = [self.send_apdu(INS_GET_VERSION)]
            except exc.APDUError as e:
                # v0 didn't support the instruction.
                self._versions = ['v0'] if e.code == 0x6d00 else []

        return self._versions

    def _do_send_apdu(self, apdu_data):
        """
        Sends an APDU to the device, and returns the response.
        """
        # Subclasses should implement this.
        raise NotImplementedError('_do_send_apdu not implemented!')

    def send_apdu(self, ins, p1=0, p2=0, data=''):
        """
        Sends an APDU to the device, and waits for a response.
        """
        if data is None:
            data = ''
        elif isinstance(data, int):
            data = chr(data)

        size = len(data)
        l0 = size >> 16 & 0xff
        l1 = size >> 8 & 0xff
        l2 = size & 0xff
        apdu_data = "%c%c%c%c%c%c%c%s%c%c" % \
            (0, ins, p1, p2, l0, l1, l2, data, 0x04, 0x00)
        try:
            resp = self._do_send_apdu(apdu_data)
        except Exception as e:
            # Wrap exception, keeping trace
            raise exc.DeviceError(e), None, sys.exc_info()[2]
        status = int(resp[-2:].encode('hex'), 16)
        data = resp[:-2]
        if status != APDU_OK:
            raise exc.APDUError(status)
        return data
