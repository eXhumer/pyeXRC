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

from random import choice
from string import ascii_letters, digits
from typing import Callable, Literal
from urllib.parse import parse_qs, urlencode, urlparse
from wsgiref.simple_server import WSGIRequestHandler, WSGIServer


class NoLoggingWSGIRequestHandler(WSGIRequestHandler):
    def log_message(self, format, *args):
        pass


class OAuth2WSGICodeFlowExchangeApp:
    def __init__(self, client_id: str, redirect_uri: str, scopes: list[str],
                 duration: Literal["temporary", "permanent"], home_endpoint: str = "/",
                 authorize_endpoint: str = "/authorize", state: str | None = None):
        if not redirect_uri.startswith(("http://localhost", "http://127.0.0.1")):
            raise ValueError("Unsupported redirect URI!")

        if duration not in ("temporary", "permanent"):
            raise ValueError("Invalid duration!")

        self.__authorize_endpoint = authorize_endpoint
        self.__redirect_uri = redirect_uri
        self.__callback_endpoint = urlparse(self.__redirect_uri).path
        self.__client_id = client_id
        self.__code = None
        self.__duration = duration
        self.__home_endpoint = home_endpoint
        self.__scopes = scopes
        self.__state = state or "".join([choice(ascii_letters + digits) for _ in range(30)])

    def __call__(self, environ: dict[str, str],
                 start_resp: Callable[[str, list[tuple[str, str]]], None]):
        REQUEST_METHOD = environ["REQUEST_METHOD"]
        PATH_INFO = environ["PATH_INFO"]
        QUERY_STRING = environ["QUERY_STRING"]
        QUERY = parse_qs(QUERY_STRING)

        if REQUEST_METHOD == "GET":
            if PATH_INFO == self.__home_endpoint:
                start_resp("200 OK", [("Content-Type", "text/html")])
                return ["".join([f'<a href="{self.__authorize_endpoint}">Authorize eXRC with ' +
                                 "Reddit account!</a>"]).encode("utf8")]

            elif PATH_INFO == self.__authorize_endpoint:
                start_resp("302 Moved Temporarily",
                           [("Location",
                             OAuth2WSGICodeFlowExchangeApp.authorize(self.__client_id,
                                                                     self.__state,
                                                                     self.__redirect_uri,
                                                                     self.__scopes,
                                                                     self.__duration))])
                return [b""]

            elif PATH_INFO == self.__callback_endpoint:
                if "error" in QUERY:
                    start_resp("200 OK", [])
                    err_val = QUERY["error"][0]

                    if err_val == "access_denied":
                        return ["User denied permission!".encode("utf8")]

                    elif err_val == "unsupported_response_type":
                        return ["Invalid initial authorization response_type!".encode("utf8")]

                    elif err_val == "invalid_scope":
                        return ["Invalid authorization scope(s) requested!".encode("utf8")]

                    elif err_val == "invalid_request":
                        return ["Invalid authorization request!".encode("utf8")]

                    else:
                        return [f"Unknown Error!\nERROR: {err_val}".encode("utf8")]

                STATE = QUERY["state"][0]
                if self.__state != STATE:
                    start_resp("200 OK", [])
                    return ["\n".join(["State Mismatch!", f"Expected: {self.__state}",
                                       f"Received: {STATE}"]).encode("utf8")]

                self.__code = QUERY["code"][0]
                start_resp("200 OK", [])
                return ["Exchange success!".encode("utf8")]

            else:
                start_resp("404 Not Found", [])
                return ["Unknown URI!".encode("utf8")]

        else:
            start_resp("405 Method Not Allowed", [])
            return ["Authorization server only supports HTTP GET requests!".encode("utf8")]

    @staticmethod
    def authorize(client_id: str, state: str, redirect_uri: str, scopes: list[str],
                  duration: Literal["temporary", "permanent"]):
        return "?".join(("https://www.reddit.com/api/v1/authorize",
                         urlencode({
                             "client_id": client_id,
                             "response_type": "code",
                             "state": state,
                             "redirect_uri": redirect_uri,
                             "scope": " ".join(scopes),
                             "duration": duration,
                         })))

    @property
    def code(self):
        return self.__code


class OAuth2WSGICodeFlowExchangeServer(WSGIServer):
    def __init__(self, host: str, port: int, client_id: str, redirect_uri: str, scopes: list[str],
                 duration: Literal["temporary", "permanent"], home_endpoint: str = "/",
                 authorize_endpoint: str = "/authorize", state: str | None = None):
        super().__init__((host, port), NoLoggingWSGIRequestHandler)
        self.__app = OAuth2WSGICodeFlowExchangeApp(client_id, redirect_uri, scopes, duration,
                                                   home_endpoint=home_endpoint,
                                                   authorize_endpoint=authorize_endpoint,
                                                   state=state)
        self.set_app(self.__app)

    @property
    def code(self):
        return self.__app.code
