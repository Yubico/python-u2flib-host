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

import requests
try:
    from urlparse import urlparse
except ImportError:
    from urllib.parse import urlparse

SUFFIX_URL = 'https://publicsuffix.org/list/effective_tld_names.dat'


class AppIDVerifier(object):

    def __init__(self):
        self._cache = {}

    def get_suffixes(self):
        if not hasattr(self, '_suffixes'):
            # Obtain the list of public DNS suffixes from
            # https://publicsuffix.org/list/effective_tld_names.dat (the client
            # may cache such data), or equivalent functionality as available on
            # the platform
            resp = requests.get(SUFFIX_URL, verify=True)
            self._suffixes = []
            for line in resp.text.splitlines():
                if not line.startswith('//') and line:
                    self._suffixes.append(line.strip())
        return self._suffixes

    def get_json(self, app_id):
        if app_id not in self._cache:
            self._cache[app_id] = self.fetch_json(app_id)
        return self._cache[app_id]

    def fetch_json(self, app_id):
        target = app_id
        while True:
            resp = requests.get(target, allow_redirects=False, verify=True)

            # If the server returns an HTTP redirect (status code 3xx) the
            # server must also send the header "FIDO-AppID-Redirect-Authorized:
            # true" and the client must verify the presence of such a header
            # before following the redirect. This protects against abuse of
            # open redirectors within the target domain by unauthorized
            # parties.
            if 300 <= resp.status_code < 400:
                if resp.headers.get('FIDO-AppID-Redirect-Authorized') != \
                        'true':
                    raise ValueError('Redirect must set '
                                     'FIDO-AppID-Redirect-Authorized: true')
                target = resp.headers['location']
            else:
                # The response must set a MIME Content-Type of
                # "application/fido.trusted-apps+json"
                if resp.headers['Content-Type'] != \
                        'application/fido.trusted-apps+json':
                    raise ValueError('Response must have Content-Type: '
                                     'application/fido.trusted-apps+json')
                return resp.json()

    def least_specific(self, url):
        # The least-specific private label is the portion of the host portion
        # of the AppID URL that matches a public suffix plus one additional
        # label to the left
        host = urlparse(url).hostname
        for suffix in self.get_suffixes():
            if host.endswith(suffix):
                n_parts = len(suffix.split('.')) + 1
                return '.'.join(host.split('.')[-n_parts:]).lower()
        raise ValueError('Hostname doesn\'t end with a public suffix')

    def valid_facets(self, app_id, facets):
        app_id_ls = self.least_specific(app_id)
        return [f for f in facets if self.facet_is_valid(app_id_ls, f)]

    def facet_is_valid(self, app_id_ls, facet):
        # The scheme of URLs in ids must identify either an application
        # identity (e.g. using the apk:, ios: or similar scheme) or an https:
        # RFC6454 Web Origin
        if facet.startswith('http://'):
            return False

        # Entries in ids using the https:// scheme must contain only scheme,
        # host and port components, with an optional trailing /. Any path,
        # query string, username/password, or fragment information is discarded
        if facet.startswith('https://'):
            url = urlparse(facet)
            facet = '%s://%s' % (url.scheme, url.hostname)
            if url.port and url.port != 443:
                facet += ':%d' % url.port

            # For each Web Origin in the TrustedFacets list, the calculation of
            # the least-specific private label in the DNS must be a
            # case-insensitive match of that of the AppID URL itself. Entries
            # that do not match must be discarded
            if self.least_specific(facet) != app_id_ls:
                return False

        return True

    def verify_facet(self, app_id, facet, version=(1, 0)):
        url = urlparse(app_id)

        # If the AppID is not an HTTPS URL, and matches the FacetID of the
        # caller, no additional processing is necessary and the operation may
        # proceed
        https = url.scheme == 'https'
        if not https and app_id == facet:
            return

        # If the caller's FacetID is an https:// Origin sharing the same host
        # as the AppID, (e.g. if an application hosted at
        # https://fido.example.com/myApp set an AppID of
        # https://fido.example.com/myAppId), no additional processing is
        # necessary and the operation may proceed
        if https and '%s://%s' % (url.scheme, url.netloc) == facet:
            return

        # Begin to fetch the Trusted Facet List using the HTTP GET method. The
        # location must be identified with an HTTPS URL.
        if not https:
            raise ValueError('AppID URL must use https.')

        data = self.get_json(app_id)
        # From among the objects in the trustedFacet array, select the one with
        # the verison matching that of the protocol message.
        for entry in data['trustedFacets']:
            e_ver = entry['version']
            if (e_ver['major'], e_ver['minor']) == version:
                trustedFacets = self.valid_facets(app_id, entry['ids'])
                break
        else:
            raise ValueError(
                'No trusted facets found for version: %r' %
                version)

        if facet not in trustedFacets:
            raise ValueError('Invalid facet: "%s", expecting one of %r' %
                            (facet, trustedFacets))


verifier = AppIDVerifier()
verify_facet = verifier.verify_facet
