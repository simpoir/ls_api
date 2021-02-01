#!/usr/bin/python3
# Copyright 2020 Simon Poirier
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
"""
Simple API library for Landscape.

This implements a simple interface as publicly documented on
https://landscape.canonical.com/static/doc/api/
"""

import base64
import datetime
import json
import os
import ssl
import sys
import hmac

from urllib.error import HTTPError
from urllib.parse import urlencode, urljoin, urlparse, quote, quote_plus
from urllib.request import urlopen

KEY_ID = os.environ.get("LANDSCAPE_API_KEY")
SECRET = os.environ.get("LANDSCAPE_API_SECRET")
URI = os.environ.get("LANDSCAPE_API_URI")
API_VERSION = "2011-08-01"
HASH = "SHA256"


class IncompleteConnectionInfo(Exception):
    """Connection info needs is incomplete.

    It should be either passed explicitly or through the LANDSCAPE_API_KEY,
    LANDSCAPE_API_SECRET, LANDSCAPE_API_URI environment variables.
    """


class APIError(Exception):
    """An server error or similar occured."""


class LandscapeApi:
    """A Landscape Api client."""

    def __init__(self, uri=URI, key_id=KEY_ID, secret=SECRET, insecure=False):
        if None in (uri, key_id, secret):
            raise IncompleteConnectionInfo
        self._uri = uri
        self._key_id = key_id
        self._secret = secret.encode("ascii")
        self._insecure = insecure

    def call(self, action, **kwargs):
        """Call an arbitrary action with named arguments"""
        ctx = {}
        if self._insecure:
            context = ctx["context"] = ssl.SSLContext()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

        kwargs["action"] = action
        kwargs["version"] = API_VERSION
        kwargs["access_key_id"] = self._key_id
        kwargs["signature_method"] = f"Hmac{HASH}"
        kwargs["signature_version"] = "2"
        kwargs["timestamp"] = (
            datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"))
        query = sorted(kwargs.items())

        url = urljoin(self._uri, "?" + urlencode(query, quote_via=quote))
        url += f"&signature={quote(self.sign(url))}"
        try:
            res = urlopen(url, **ctx)
        except HTTPError as err:
            res = err

        data = res.read()
        try:
            return json.loads(data)
        except json.JSONDecodeError:
            raise APIError(data)

    def sign(self, url, method=HASH):
        """Sign an API request."""
        _, host, path, _, query, _ = urlparse(url)
        to_sign = f"GET\n{host.lower()}\n{path}\n{query}"
        return base64.b64encode(
            hmac.HMAC(self._secret, to_sign.encode("ASCII"), method).digest())


def main():
    """Call the API from the command-line."""
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-k", "--insecure", default=False, action="store_true",
        help="ignore certificate errors")
    parser.add_argument("action")
    args, unparsed = parser.parse_known_args()

    kw = {}
    for arg in unparsed:
        k, _, v = arg.partition("=")
        if ',' in v:
            # make fancy arrays from commas
            for i, vv in enumerate(v.split(",")):
                kw[f"{k}.{i}"] = vv
        else:
            kw[k] = v

    json.dump(
        LandscapeApi(insecure=args.insecure).call(args.action, **kw),
        sys.stdout,
    )


if __name__ == "__main__":
    main()
