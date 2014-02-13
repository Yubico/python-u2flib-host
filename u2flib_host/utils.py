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

from base64 import urlsafe_b64decode, urlsafe_b64encode
from hashlib import sha256

__all__ = [
    'u2str',
    'websafe_encode',
    'websafe_decode',
    'H'
]


def u2str(data):
    """Recursivly converts unicode object to UTF-8 formatted strings."""
    if isinstance(data, dict):
        return {u2str(k): u2str(v) for k, v in data.iteritems()}
    elif isinstance(data, list):
        return [u2str(x) for x in data]
    elif isinstance(data, unicode):
        return data.encode('utf-8')
    else:
        return data


def websafe_decode(data):
    if isinstance(data, unicode):
        data = data.encode('utf-8')
    data += '=' * (-len(data) % 4)
    return urlsafe_b64decode(data)


def websafe_encode(data):
    return urlsafe_b64encode(data).replace('=', '')


def H(data):
    f = sha256()
    f.update(data)
    return f.digest()
