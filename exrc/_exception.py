# pyeXRC - Python Reddit client
# Copyright © 2023 - exhumer

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, version 3 of the License.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

from datetime import datetime, timezone

from httpx import Response

from ._type import OAuth2Token


class OAuth2TokenException(Exception):
    pass


class OAuth2ExpiredTokenException(Exception):
    def __init__(self, token: OAuth2Token, expiry: datetime):
        super().__init__(f"OAuth2 token {token['access_token']} expired at {expiry}!")


class OAuth2RevokedTokenException(OAuth2TokenException):
    def __init__(self, token: OAuth2Token):
        self.__token = token
        self.__msg = f"Token {token['access_token']} has been revoked!"
        super().__init__(self.__msg)

    @property
    def message(self):
        return self.__msg

    @property
    def token(self):
        return self.__token


class RateLimitException(Exception):
    def __init__(self, reset: datetime):
        self.__reset = reset
        super().__init__(f"Rate limited until {reset.isoformat()}!")

    @property
    def seconds_until_reset(self):
        if self.__reset > datetime.now(tz=timezone.utc):
            return int((self.__reset - datetime.now(tz=timezone.utc)).total_seconds())

        return 0


class RESTException(Exception):
    def __init__(self, res: Response):
        self.__res = res
        super().__init__(f"REST exception occurred with status code {res.status_code}!\n" +
                         f"Response: {res.request.read()}")

    @property
    def response(self):
        return self.__res
