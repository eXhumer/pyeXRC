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

from __future__ import annotations
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime as html_date_parser
from json import dump as json_dump, load as json_load
from pathlib import Path
from random import SystemRandom
from string import ascii_letters, digits
from typing import List, Dict, Tuple, Callable
from urllib.parse import urlencode, urlparse, parse_qs
from webbrowser import open as webbrowser_open
from wsgiref.simple_server import make_server

from requests import Session
from requests.auth import HTTPBasicAuth

from . import __version__
from .exception import (
    OAuth2Exception,
    ResponseException,
)
from .utils import NoLoggingWSGIRequestHandler


class OAuth2WSGICodeFlowExchangeApp:
    def __init__(
        self,
        client_id: str,
        callback_url: str,
        scopes: List[str],
        state: str,
        duration: str,
    ):
        if not callback_url.startswith((
            "http://localhost",
            "http://127.0.0.1",
        )):
            raise ValueError("Unsupported redirect URI!")

        if duration not in ("temporary", "permanent"):
            raise ValueError("Invalid duration!")

        self.__authcode: str | None = None
        self.__client_id: str = client_id
        self.__callback_url: str = callback_url
        self.__scopes: List[str] = scopes
        self.__state: str = state
        self.__duration: str = duration
        self.__callback_endpoint = urlparse(self.__callback_url).path
        self.home_endpoint = "/"
        self.authorize_endpoint = "/authorize"

    def __call__(
        self,
        environ: Dict[str, str],
        start_resp: Callable[[str, List[Tuple[str, str]]], None],
    ):
        req_method = environ["REQUEST_METHOD"]
        req_uri = environ["PATH_INFO"]
        req_query = parse_qs(environ["QUERY_STRING"])

        if req_method == "GET":
            if req_uri == self.home_endpoint:
                start_resp("200 OK", [
                    ("Content-Type", "text/html"),
                ])
                return ["".join([
                    f'<a href="{self.authorize_endpoint}">',
                    "Authorize eXRC with Reddit account!",
                    "</a>",
                ]).encode("utf8")]

            elif req_uri == self.authorize_endpoint:
                start_resp(
                    "302 Moved Temporarily",
                    [
                        (
                            "Location",
                            OAuth2Credential.authorize(
                                self.__client_id,
                                self.__state,
                                self.__callback_url,
                                self.__scopes,
                                self.__duration,
                            ),
                        ),
                    ],
                )
                return [b""]

            elif req_uri == self.__callback_endpoint:
                if "error" in req_query:
                    start_resp("200 OK", [])
                    err_val = req_query["error"]

                    if err_val == "access_denied":
                        return ["User denied permission!".encode("utf8")]

                    elif err_val == "unsupported_response_type":
                        return [
                            "Invalid initial authorization response_type!"
                            .encode("utf8")
                        ]

                    elif err_val == "invalid_scope":
                        return [
                            "Invalid authorization scope(s) requested!"
                            .encode("utf8")
                        ]

                    elif err_val == "invalid_request":
                        return ["Invalid authorization request!"
                                .encode("utf8")]

                    else:
                        return ["Unknown Error!"
                                + f"\nERROR: {err_val}".encode("utf8")]

                req_state = req_query["state"][0]
                if self.__state != req_state:
                    start_resp("200 OK", [])
                    return [
                        "\n".join([
                            "State Mismatch!",
                            f"Expected: {self.__state}",
                            f"Received: {req_state}"
                        ]).encode("utf8")
                    ]

                self.__authcode = req_query["code"][0]
                start_resp("200 OK", [])
                return ["Exchange success!".encode("utf8")]

            else:
                start_resp("404 Not Found", [])
                return ["Unknown URI!".encode("utf8")]

        else:
            start_resp("405 Method Not Allowed", [])
            return [
                "Authorization server only supports".encode("utf8"),
                " HTTP GET requests!".encode("utf8"),
            ]

    @property
    def authcode(self):
        return self.__authcode


class OAuth2Credential:
    auth_base_url = "https://www.reddit.com"
    revoke_endpoint = "api/v1/revoke_token"
    access_endpoint = "api/v1/access_token"
    authorize_endpoint = "api/v1/authorize"

    @staticmethod
    def authorize(
        client_id: str,
        state: str,
        callback_url: str,
        scopes: List[str],
        duration: str,
    ):
        return "?".join((
            "/".join((
                OAuth2Credential.auth_base_url,
                OAuth2Credential.authorize_endpoint,
            )),
            urlencode({
                "client_id": client_id,
                "response_type": "code",
                "state": state,
                "redirect_uri": callback_url,
                "scope": " ".join(scopes),
                "duration": duration,
            }),
        ))

    @staticmethod
    def valid_oauth_scopes(session: Session) -> Dict[str, Dict[str, str]]:
        res = session.get(
            "https://www.reddit.com/api/v1/scopes",
            headers={
                "User-Agent": f"{__package__}/{__version__}",
            },
        )

        if res.status_code != 200:
            raise ResponseException(
                res, "Failed to retrieve Reddit valid scopes!"
            )

        return res.json()

    def __init__(
        self,
        access_token: str,
        expires_at: datetime,
        scopes: List[str],
        token_type: str,
        device_id: str | None = None,
        refresh_token: str | None = None,
    ):
        self.__access_token = access_token
        self.__expires_at = expires_at
        self.__scopes = scopes
        self.__token_type = token_type
        self.__device_id = device_id
        self.__refresh_token = refresh_token

    @property
    def access_token(self):
        return self.__access_token

    @property
    def expires_at(self):
        return self.__expires_at

    @property
    def expired(self):
        return datetime.now(tz=timezone.utc) >= self.__expires_at

    @property
    def scopes(self):
        return self.__scopes

    @property
    def token_type(self):
        return self.__token_type

    @property
    def refresh_token(self):
        return self.__refresh_token

    @property
    def device_id(self):
        return self.__device_id

    @property
    def authorization(self):
        return f"{self.__token_type} {self.__access_token}"

    def revoke(self, session: Session, client_id: str, client_secret: str):
        data = urlencode({
            "token": self.__access_token,
            "token_type_hint": "access_token",
        })

        res = session.post(
            "/".join((
                OAuth2Credential.auth_base_url,
                OAuth2Credential.revoke_endpoint,
            )),
            data=data,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Content-Length": f"{len(data)}",
                "User-Agent": f"{__package__}/{__version__}",
            },
            auth=HTTPBasicAuth(client_id, client_secret),
        )

        if self.__refresh_token is not None:
            data = urlencode({
                "token": self.__refresh_token,
                "token_type_hint": "refresh_token",
            })

            res = session.post(
                "/".join((
                    OAuth2Credential.auth_base_url,
                    OAuth2Credential.revoke_endpoint,
                )),
                data=data,
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Content-Length": f"{len(data)}",
                    "User-Agent": f"{__package__}/{__version__}",
                },
                auth=HTTPBasicAuth(client_id, client_secret),
            )

        return res

    def refresh(self, session: Session, client_id: str, client_secret: str):
        if self.__refresh_token is None:
            raise OAuth2Exception("Attempting to refresh credential without" +
                                  " refresh token!")

        data = urlencode({
            "grant_type": "refresh_token",
            "refresh_token": self.__refresh_token,
        })

        res = session.post(
            "/".join((
                OAuth2Credential.auth_base_url,
                OAuth2Credential.access_endpoint,
            )),
            data=data,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Content-Length": f"{len(data)}",
                "User-Agent": f"{__package__}/{__version__}",
            },
            auth=HTTPBasicAuth(client_id, client_secret),
        )

        if res.status_code != 200:
            raise ResponseException(
                res,
                "Failed to refresh OAuth2 credential!",
            )

        token_data = res.json()
        self.__access_token = token_data["access_token"]
        if "refresh_token" in token_data:
            self.__refresh_token = token_data["refresh_token"]
        self.__expires_at = html_date_parser(res.headers["Date"]) \
            + timedelta(seconds=token_data["expires_in"])
        self.__scopes = token_data["scope"].split(" ")
        self.__token_type = token_data["token_type"]

        if "refresh_token" in token_data:
            self.__refresh_token = token_data["refresh_token"]

    def save_to_file(self, token_path: Path):
        json_data = {
            "access_token": self.__access_token,
            "expires_at": self.__expires_at.isoformat(),
            "token_type": self.__token_type,
            "scopes": self.__scopes,
        }

        if self.__device_id is not None:
            json_data.update({"device_id": self.__device_id})

        if self.__refresh_token is not None:
            json_data.update({"refresh_token": self.__refresh_token})

        with token_path.open(mode="w") as out_stream:
            json_dump(
                json_data,
                out_stream,
                sort_keys=True,
                indent=4,
            )

    @classmethod
    def load_from_file(cls, token_path: Path):
        with token_path.open(mode="r") as token_stream:
            token_data = json_load(token_stream)
            device_id = (
                token_data["device_id"]
                if "device_id" in token_data
                else None
            )
            refresh_token = (
                token_data["refresh_token"]
                if "refresh_token" in token_data
                else None
            )

            return cls(
                token_data["access_token"],
                datetime.fromisoformat(token_data["expires_at"]),
                token_data["scopes"],
                token_data["token_type"],
                refresh_token=refresh_token,
                device_id=device_id,
            )

    @classmethod
    def password_grant(
        cls,
        session: Session,
        client_id: str,
        client_secret: str,
        username: str,
        password: str,
        two_factor_code: str | None = None,
    ):
        if two_factor_code is not None:
            if len(two_factor_code) == 6 and two_factor_code.isnumeric():
                raise ValueError("Invalid two factor code! Must be of length" +
                                 " 6 and must be numeric!")

            password = f"{password}:{two_factor_code}"

        data = urlencode(
            {
                "grant_type": "password",
                "username": username,
                "password": password,
            }
        )

        res = session.post(
            "/".join((
                OAuth2Credential.auth_base_url,
                OAuth2Credential.access_endpoint,
            )),
            data=data,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Content-Length": f"{len(data)}",
                "User-Agent": f"{__package__}/{__version__}",
            },
            auth=HTTPBasicAuth(client_id, client_secret),
        )

        if res.status_code != 200:
            raise ResponseException(
                res,
                "Failed to get OAuth2 credential via password flow!",
            )

        return cls(
            res.json()["access_token"],
            (
                html_date_parser(res.headers["Date"])
                + timedelta(seconds=res.json()["expires_in"])
            ),
            res.json()["scope"].split(" "),
            res.json()["token_type"],
        )

    @classmethod
    def client_credential_grant(
        cls,
        session: Session,
        client_id: str,
        client_secret: str,
    ):
        data = urlencode({"grant_type": "client_credentials"})

        res = session.post(
            "/".join((
                OAuth2Credential.auth_base_url,
                OAuth2Credential.access_endpoint,
            )),
            data=data,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Content-Length": f"{len(data)}",
                "User-Agent": f"{__package__}/{__version__}",
            },
            auth=HTTPBasicAuth(client_id, client_secret),
        )

        if res.status_code != 200:
            raise ResponseException(
                res,
                "Failed to get OAuth2 credential via client credential flow!",
            )

        return cls(
            res.json()["access_token"],
            (
                html_date_parser(res.headers["Date"])
                + timedelta(seconds=res.json()["expires_in"])
            ),
            res.json()["scope"].split(" "),
            res.json()["token_type"],
        )

    @classmethod
    def installed_client_grant(
        cls,
        session: Session,
        client_id: str,
        client_secret: str,
        device_id: str = "".join([
            SystemRandom().choice(ascii_letters + digits)
            for _ in range(30)
        ]),
    ):
        data = urlencode(
            {
                "grant_type": "https://oauth.reddit.com/grants/" +
                "installed_client",
                "device_id": device_id,
            }
        )

        res = session.post(
            "/".join((
                OAuth2Credential.auth_base_url,
                OAuth2Credential.access_endpoint,
            )),
            data=data,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Content-Length": f"{len(data)}",
                "User-Agent": f"{__package__}/{__version__}",
            },
            auth=HTTPBasicAuth(client_id, client_secret),
        )

        if res.status_code != 200:
            raise ResponseException(
                res,
                "Failed to get OAuth2 credential via installed " +
                "application flow!",
            )

        return cls(
            client_id=client_id,
            access_token=res.json()["access_token"],
            token_type=res.json()["token_type"],
            scopes=res.json()["scope"].split(" "),
            expires_at=(
                html_date_parser(res.headers["Date"])
                + timedelta(seconds=res.json()["expires_in"])
            ),
            device_id=res.json()["device_id"],
        )

    @classmethod
    def authorization_code_grant(
        cls,
        session: Session,
        client_id: str,
        client_secret: str,
        authcode: str,
        callback_url: str,
    ):
        data = urlencode({
            "code": authcode,
            "grant_type": "authorization_code",
            "redirect_uri": callback_url,
        })

        res = session.post(
            "/".join((
                OAuth2Credential.auth_base_url,
                OAuth2Credential.access_endpoint,
            )),
            data=data,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Content-Length": f"{len(data)}",
                "User-Agent": f"{__package__}/{__version__}",
            },
            auth=HTTPBasicAuth(client_id, client_secret),
        )

        if res.status_code != 200:
            raise ResponseException(
                res,
                "Failed to retrieve OAuth2 credential from authorization " +
                "code!",
            )

        token_data = res.json()
        refresh_token = (
            token_data["refresh_token"]
            if "refresh_token" in token_data
            else None
        )

        return cls(
            token_data["access_token"],
            (
                html_date_parser(res.headers["Date"]) +
                timedelta(seconds=token_data["expires_in"])
            ),
            token_data["scope"].split(" "),
            token_data["token_type"],
            refresh_token=refresh_token,
        )

    @classmethod
    def localserver_code_flow(
        cls,
        session: Session,
        client_id: str,
        client_secret: str,
        callback_url: str,
        duration: str,
        scopes: List[str],
        state: str,
    ):
        netloc = urlparse(callback_url).netloc
        netloc_parts = netloc.split(":", maxsplit=1)
        host = netloc_parts[0]
        port = int(netloc_parts[1]) if len(netloc_parts) == 2 else 80
        wsgi_app = OAuth2WSGICodeFlowExchangeApp(
            client_id,
            callback_url,
            scopes,
            state,
            duration,
        )
        wsgi_server = make_server(
            host,
            port,
            wsgi_app,
            handler_class=NoLoggingWSGIRequestHandler,
        )
        webbrowser_open(f"http://{netloc}/")

        while wsgi_app.authcode is None:
            wsgi_server.handle_request()

        return cls.authorization_code_grant(
            session,
            client_id,
            client_secret,
            wsgi_app.authcode,
            callback_url,
        )
