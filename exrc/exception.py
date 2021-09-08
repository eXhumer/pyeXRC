# eXRC - Reddit OAuth2 Client
# Copyright (C) 2021 - eXhumer

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3 of the License.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

from requests import Response


class OAuth2Exception(Exception):
    def __init__(self, *args) -> None:
        super().__init__(*args)


class ResponseException(Exception):
    def __init__(self, resp: Response, *args) -> None:
        self.__resp = resp
        super().__init__(*args)

    def response(self) -> Response:
        return self.__resp


class InvalidInvocationException(Exception):
    def __init__(self, *args) -> None:
        super().__init__(*args)
