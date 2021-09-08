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
from pkg_resources import require
from random import SystemRandom
from string import ascii_letters, digits
from typing import Type, Optional, List, Dict, Any, Tuple, Callable
from urllib.parse import urlencode, urlparse, parse_qs
from webbrowser import open as webbrowser_open
from wsgiref.simple_server import make_server

from requests import Session, Response
from requests.auth import HTTPBasicAuth
from requests.utils import default_user_agent

from .exception import (
    OAuth2Exception,
    ResponseException,
    InvalidInvocationException,
)
from .utils import NoLoggingWSGIRequestHandler


class OAuth2ClientCredential(object):
    def __init__(self, **auth_options: str) -> None:
        super().__init__()
        self.__client_id = (
            auth_options["client_id"]
            if "client_id" in auth_options
            and isinstance(auth_options["client_id"], str)
            else None
        )
        self.__client_secret = (
            auth_options["client_secret"]
            if "client_secret" in auth_options
            and isinstance(auth_options["client_secret"], str)
            else None
        )

    @property
    def valid(self) -> bool:
        return self.__client_id is not None

    @property
    def client_id(self) -> str | None:
        return self.__client_id

    @property
    def client_secret(self) -> str | None:
        return self.__client_secret

    def revoke_credential(self) -> List[Response]:
        self.__client_id = None
        self.__client_secret = None
        return []


class OAuth2WSGIAuthCodeExchangeApp(object):
    """
    Keyword Arguments
    ------
    client_id: str
    redirect_uri: str
    scopes: List[str]
    state: str
    duration: str
    """
    def __init__(
        self,
        **auth_options: str | List[str] | OAuth2ClientCredential,
    ) -> None:
        super().__init__()
        self.__authcode: Optional[str] = None
        self.__client_id: str = auth_options["client_id"]
        self.__redirect_uri: str = auth_options["redirect_uri"]
        self.__scopes: List[str] = auth_options["scopes"]
        self.__state: str = auth_options["state"]
        self.__duration: str = auth_options["duration"]
        self.__external_endpoint = "/auth"
        self.__callback_endpoint = urlparse(self.__redirect_uri).path

        if (
            self.__duration not in ["permanent", "temporary"]
            or not self.__redirect_uri.startswith(
                ("http://localhost", "http://127.0.0.1")
            )
        ):
            raise InvalidInvocationException(
                "One or more of the provided keyword arguments in invalid!"
            )

    def __call__(
        self,
        environ: Dict[str, str],
        start_resp: Callable[[str, List[Tuple[str, str]]], None],
    ) -> bytes:
        req_method = environ["REQUEST_METHOD"]
        req_uri = environ["PATH_INFO"]
        req_query = parse_qs(environ["QUERY_STRING"])

        if req_method == "GET":
            if req_uri == "/":
                start_resp("200 OK", [
                    ("Content-Type", "text/html"),
                ])
                return ["".join([
                    f'<a href="{self.__external_endpoint}">',
                    "Authenticate with Reddit user account!",
                    "</a>",
                ]).encode("utf8")]

            elif req_uri == self.__external_endpoint:
                start_resp(
                    "302 Moved Temporarily",
                    [("Location", self.__authorize_url)],
                )
                return []

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
                "Authentication server only supports".encode("utf8"),
                " HTTP GET requests!".encode("utf8"),
            ]

    @property
    def authcode(self) -> str | None:
        return self.__authcode

    @property
    def __authorize_url(self) -> str:
        auth_qs = {
            "client_id": self.__client_id,
            "response_type": "code",
            "state": self.__state,
            "redirect_uri": self.__redirect_uri,
            "scope": " ".join(self.__scopes),
            "duration": self.__duration,
        }

        return f"https://www.reddit.com/api/v1/authorize?{urlencode(auth_qs)}"


class OAuth2Credential(OAuth2ClientCredential):
    __client_version = require("eXRC")[0].version
    req_session = Session()
    auth_base_url = "https://www.reddit.com"
    revoke_endpoint = "/api/v1/revoke_token"
    access_endpoint = "/api/v1/access_token"

    @staticmethod
    def client_version() -> str:
        return OAuth2Credential.__client_version

    @staticmethod
    def __session_ua_check(**auth_options: str):
        if "user_agent" in auth_options:
            OAuth2Credential.req_session.headers["User-Agent"] = \
                auth_options["user_agent"]

        if OAuth2Credential.req_session.headers["User-Agent"] == \
                default_user_agent:
            OAuth2Credential.req_session.headers["User-Agent"] = \
                f"eXRC/{OAuth2Credential.__client_version}"

    @staticmethod
    def valid_oauth_scopes() -> Dict[str, Dict[str, str]]:
        OAuth2Credential.__session_ua_check()
        res = OAuth2Credential.req_session.get(
            "https://www.reddit.com/api/v1/scopes"
        )

        if res.status_code != 200:
            raise ResponseException(
                res, "ERROR: Failed to retrieve Reddit valid scopes!"
            )

        return res.json()

    def __init__(
        self,
        **auth_options: str | datetime | List[str],
    ) -> None:
        super().__init__(**auth_options)
        OAuth2Credential.__session_ua_check(**auth_options)

        self.__access_token: Optional[str] = (
            auth_options["access_token"]
            if (
                "access_token" in auth_options
                and isinstance(auth_options["access_token"], str)
            )
            else None
        )
        self.__expires_at: Optional[datetime] = (
            auth_options["expires_at"]
            if (
                "expires_at" in auth_options
                and isinstance(auth_options["expires_at"], datetime)
            )
            else None
        )
        self.__scopes: Optional[List[str]] = (
            auth_options["scopes"]
            if (
                "scopes" in auth_options
                and isinstance(auth_options["scopes"], list)
            )
            else None
        )
        if self.__scopes is not None:
            for scope in self.__scopes:
                if not isinstance(scope, str):
                    self.__scopes = None
                    break
        self.__token_type: Optional[str] = (
            auth_options["token_type"]
            if (
                "token_type" in auth_options
                and isinstance(auth_options["token_type"], str)
            )
            else None
        )
        self.__device_id: Optional[str] = (
            auth_options["device_id"]
            if (
                "device_id" in auth_options
                and isinstance(auth_options["device_id"], str)
            )
            else None
        )
        self.__refresh_token: Optional[str] = (
            auth_options["refresh_token"]
            if (
                "refresh_token" in auth_options
                and isinstance(auth_options["refresh_token"], str)
            )
            else None
        )

    @property
    def valid(self) -> bool:
        # Check for client credential first
        return super().valid and (
            self.__access_token is not None
            and self.__expires_at is not None
            and self.__token_type is not None
            and self.__scopes is not None
        )

    @property
    def expired(self) -> bool:
        if self.__expires_at is not None:
            return datetime.now(tz=timezone.utc) >= self.__expires_at

        return True

    @property
    def access_token(self) -> str | None:
        return self.__access_token

    @property
    def refresh_token(self) -> str | None:
        return self.__refresh_token

    @property
    def device_id(self) -> str | None:
        return self.__device_id

    @property
    def scopes(self) -> List[str] | None:
        return self.__scopes

    @property
    def token_type(self) -> str | None:
        return self.__token_type

    @property
    def expires_at(self) -> datetime | None:
        return self.__expires_at

    @property
    def json(self) -> Dict[str, Any]:
        if self.valid:
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

            return json_data

        return {}

    def revoke_credential(self) -> List[Response]:
        OAuth2Credential.__session_ua_check()

        results = []

        if self.__access_token is not None and not self.expired:
            data = urlencode({
                "token": self.__access_token,
                "token_type_hint": "access_token",
            })

            results.append(
                OAuth2Credential.req_session.post(
                    OAuth2Credential.auth_base_url
                    + OAuth2Credential.revoke_endpoint,
                    data=data,
                    headers={
                        "Content-Type": "application/x-www-form-urlencoded",
                        "Content-Length": f"{len(data)}",
                    },
                    auth=HTTPBasicAuth(
                        self.client_id,
                        self.client_secret
                        if self.client_secret is not None
                        else "",
                    ),
                )
            )

        if self.__refresh_token is not None:
            data = urlencode({
                "token": self.__refresh_token,
                "token_type_hint": "refresh_token",
            })

            results.append(
                OAuth2Credential.req_session.post(
                    OAuth2Credential.auth_base_url
                    + OAuth2Credential.revoke_endpoint,
                    data=data,
                    headers={
                        "Content-Type": "application/x-www-form-urlencoded",
                        "Content-Length": f"{len(data)}",
                    },
                    auth=HTTPBasicAuth(
                        self.client_id,
                        self.client_secret
                        if self.client_secret is not None
                        else "",
                    ),
                )
            )

        super().revoke_credential()

        return results

    def save_credential(self, **save_options: Path) -> None:
        with save_options["token_path"].open(mode="w") as out_token_stream:
            json_dump(
                self.json,
                out_token_stream,
                sort_keys=True,
                indent=4,
            )

    @classmethod
    def load_credential(
        cls: Type[OAuth2Credential],
        **load_options: Path | str,
    ) -> OAuth2Credential:
        OAuth2Credential.__session_ua_check(**load_options)
        token_path = Path(load_options["token_path"])

        if (
            "client_id" in load_options
            and isinstance(load_options["client_id"], str)
            and token_path.exists()
        ):
            with token_path.open(mode="r") as token_stream:
                token_data = json_load(token_stream)
                valid_token_data = (
                    (
                        "access_token" in token_data
                        and isinstance(token_data["access_token"], str)
                    ) and (
                        "expires_at" in token_data
                        and isinstance(token_data["expires_at"], str)
                    ) and (
                        "scopes" in token_data
                        and isinstance(token_data["scopes"], list)
                        # missing check for each list item
                    ) and (
                        "token_type" in token_data
                        and isinstance(token_data["token_type"], str)
                    )
                )

                if valid_token_data is True:
                    client_secret = token_data["client_secret"] if (
                        "client_secret" in token_data
                        and isinstance(token_data["client_secret"], str)
                    ) else None
                    refresh_token = token_data["refresh_token"] if (
                        "refresh_token" in token_data
                        and isinstance(token_data["refresh_token"], str)
                    ) else None
                    device_id = token_data["device_id"] if (
                        "device_id" in token_data
                        and isinstance(token_data["device_id"], str)
                    ) else None

                    return cls(
                        client_id=load_options["client_id"],
                        client_secret=client_secret,
                        access_token=token_data["access_token"],
                        expires_at=datetime.fromisoformat(
                            token_data["expires_at"]
                        ),
                        scopes=token_data["scopes"],
                        token_type=token_data["token_type"],
                        refresh_token=refresh_token,
                        device_id=device_id,
                    )

        return cls()

    @classmethod
    def auth_new_user_script(
        cls: Type[OAuth2Credential],
        **auth_options: str | int,
    ) -> OAuth2Credential:
        OAuth2Credential.__session_ua_check(**auth_options)

        client_id = (
            auth_options["client_id"]
            if (
                "client_id" in auth_options
                and isinstance(auth_options["client_id"], str)
            )
            else None
        )
        client_secret = (
            auth_options["client_secret"]
            if (
                "client_secret" in auth_options
                and isinstance(auth_options["client_secret"], str)
            )
            else None
        )
        username = (
            auth_options["username"]
            if (
                "username" in auth_options
                and isinstance(auth_options["username"], str)
            )
            else None
        )
        password = (
            auth_options["password"]
            if (
                "password" in auth_options
                and isinstance(auth_options["password"], str)
            )
            else None
        )
        two_factor_code = (
            auth_options["two_factor_code"]
            if (
                "two_factor_code" in auth_options
                and isinstance(auth_options["two_factor_code"], str)
                and len(auth_options["two_factor_code"]) == 6
                and auth_options["two_factor_code"].isnumeric()
            )
            else None
        )
        if two_factor_code is not None:
            password = f"{password}:{two_factor_code}"

        if (
            username is not None
            and password is not None
            and client_id is not None
            and client_secret is not None
        ):
            data = urlencode(
                {
                    "grant_type": "password",
                    "username": username,
                    "password": password,
                }
            )

            res = OAuth2Credential.req_session.post(
                OAuth2Credential.auth_base_url
                + OAuth2Credential.access_endpoint,
                data=data,
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Content-Length": f"{len(data)}",
                },
                auth=HTTPBasicAuth(client_id, client_secret),
            )

            if res.status_code == 200:
                access_token = res.json()["access_token"]
                expires_at = (
                    html_date_parser(res.headers["Date"])
                    + timedelta(seconds=res.json()["expires_in"])
                )
                scopes = res.json()["scope"].split(" ")
                token_type = res.json()["token_type"]
                return cls(
                    client_id=client_id,
                    client_secret=client_secret,
                    access_token=access_token,
                    expires_at=expires_at,
                    scopes=scopes,
                    token_type=token_type,
                )

            elif res.status_code == 401:
                raise ResponseException(
                    res, "ERROR: Invalid client credential!",
                )

        return cls()

    @classmethod
    def auth_client_credential(
        cls: Type[OAuth2Credential],
        **auth_options: str | int,
    ) -> OAuth2Credential:
        OAuth2Credential.__session_ua_check(**auth_options)

        client_id = (
            auth_options["client_id"]
            if (
                "client_id" in auth_options
                and isinstance(auth_options["client_id"], str)
            )
            else None
        )
        client_secret = (
            auth_options["client_secret"]
            if (
                "client_secret" in auth_options
                and isinstance(auth_options["client_secret"], str)
            )
            else None
        )

        if client_id is not None and client_secret is not None:
            data = urlencode({"grant_type": "client_credentials"})

            res = OAuth2Credential.req_session.post(
                OAuth2Credential.auth_base_url
                + OAuth2Credential.access_endpoint,
                data=data,
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Content-Length": f"{len(data)}",
                },
                auth=HTTPBasicAuth(client_id, client_secret),
            )

            if res.status_code == 200:
                return cls(
                    client_id=client_id,
                    client_secret=client_secret,
                    access_token=res.json()["access_token"],
                    scopes=res.json()["scope"].split(" "),
                    expires_at=(
                        html_date_parser(res.headers["Date"])
                        + timedelta(seconds=res.json()["expires_in"])
                    ),
                    token_type=res.json()["token_type"],
                )

        return cls()

    @classmethod
    def auth_installed_client(
        cls: Type[OAuth2Credential],
        **auth_options: str,
    ) -> OAuth2Credential:
        OAuth2Credential.__session_ua_check(**auth_options)

        client_id = (
            auth_options["client_id"]
            if (
                "client_id" in auth_options
                and isinstance(auth_options["client_id"], str)
            )
            else None
        )

        if client_id is not None:
            client_secret = (
                auth_options["client_secret"]
                if (
                    "client_secret" in auth_options
                    and isinstance(auth_options["client_secret"], str)
                )
                else ""
            )
            device_id = (
                auth_options["device_id"]
                if (
                    "device_id" in auth_options
                    and isinstance(auth_options["device_id"], str)
                )
                else "".join([
                    SystemRandom().choice(ascii_letters + digits)
                    for _ in range(30)
                ])
            )

            data = urlencode(
                {
                    "grant_type": "https://oauth.reddit.com/grants/" +
                    "installed_client",
                    "device_id": device_id,
                }
            )

            res = OAuth2Credential.req_session.post(
                OAuth2Credential.auth_base_url
                + OAuth2Credential.access_endpoint,
                data=data,
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Content-Length": f"{len(data)}",
                },
                auth=HTTPBasicAuth(client_id, client_secret),
            )

            if res.status_code == 200:
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

            elif res.status_code == 401:
                raise ResponseException(
                    res, "ERROR: Invalid client credential!",
                )

        return cls()

    @classmethod
    def from_authorization_code(
        cls: Type[OAuth2Credential],
        **auth_options: str | List[str],
    ) -> OAuth2Credential:
        OAuth2Credential.__session_ua_check(**auth_options)

        if (
            "authcode" in auth_options
            and "client_id" in auth_options
        ):
            data = urlencode({
                "code": auth_options["authcode"],
                "grant_type": "authorization_code",
                "redirect_uri": auth_options["redirect_uri"],
            })

            res = OAuth2Credential.req_session.post(
                OAuth2Credential.auth_base_url
                + OAuth2Credential.access_endpoint,
                data=data,
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Content-Length": f"{len(data)}",
                },
                auth=HTTPBasicAuth(
                    auth_options["client_id"],
                    auth_options["client_secret"]
                    if "client_secret" in auth_options
                    else "",
                ),
            )

            if res.status_code == 200:
                token_data = res.json()

                return cls(
                    client_id=auth_options["client_id"],
                    client_secret=auth_options["client_secret"]
                    if "client_secret" in auth_options
                    else "",
                    access_token=token_data["access_token"],
                    token_type=token_data["token_type"],
                    expires_at=html_date_parser(res.headers["Date"]) +
                    timedelta(seconds=token_data["expires_in"]),
                    scopes=token_data["scope"].split(" "),
                    refresh_token=token_data["refresh_token"]
                    if "refresh_token" in token_data
                    else None,
                )

        return cls()

    def refresh_credential(self) -> None:
        if self.valid:
            client_id = self.client_id
            client_secret = self.client_secret

            if not self.expired:
                self.revoke_credential()

            data = urlencode({
                "grant_type": "refresh_token",
                "refresh_token": self.__refresh_token,
            })

            res = OAuth2Credential.req_session.post(
                OAuth2Credential.auth_base_url
                + OAuth2Credential.access_endpoint,
                data=data,
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Content-Length": f"{len(data)}",
                },
                auth=HTTPBasicAuth(client_id, client_secret),
            )

            if res.status_code == 200:
                token_data = res.json()
                self._client_id = client_id
                self._client_secret = client_secret
                self.__access_token = token_data["access_token"]
                if "refresh_token" in token_data:
                    self.__refresh_token = token_data["refresh_token"]
                self.__expires_at = html_date_parser(res.headers["Date"]) \
                    + timedelta(seconds=token_data["expires_in"])
                self.__scopes = token_data["scope"].split(" ")
                self.__token_type = token_data["token_type"]
                return

            elif res.status_code == 401:
                raise ResponseException(
                    res, "ERROR: Invalid client credential!"
                )

            else:
                raise ResponseException(
                    res, "ERROR: Unknown error while refreshing credential!"
                )

        else:
            raise OAuth2Exception("Invalid credential!")

    @classmethod
    def auth_new_user_localserver_authcode_flow(
        cls: Type[OAuth2Credential],
        **auth_options: str | List[str],
    ) -> OAuth2Credential:
        if (
            "client_id" in auth_options
            and "redirect_uri" in auth_options
            and (
                auth_options["redirect_uri"].startswith("http://localhost")
                or auth_options["redirect_uri"].startswith("http://127.0.0.1")
            )
        ):
            netloc: str = urlparse(auth_options["redirect_uri"]).netloc
            netloc_parts = netloc.split(":", maxsplit=1)
            host = netloc_parts[0]
            port = int(netloc_parts[1]) if len(netloc_parts) == 2 else 80
            wsgi_app = OAuth2WSGIAuthCodeExchangeApp(**auth_options)
            wsgi_server = make_server(
                host,
                port,
                wsgi_app,
                handler_class=NoLoggingWSGIRequestHandler,
            )
            webbrowser_open(f"http://{netloc}/")

            while wsgi_app.authcode is None:
                wsgi_server.handle_request()

            return cls.from_authorization_code(
                authcode=wsgi_app.authcode,
                **auth_options,
            )

        return cls()

    @property
    def authorization(self) -> str:
        if self.valid is False:
            raise OAuth2Exception(
                "ERROR: No authorization available for invalid credential!",
            )

        if self.expired:
            if self.__refresh_token is None:
                raise OAuth2Exception(
                    "ERROR: Authorization credential expired with no "
                    + "refresh token!",
                )

            self.refresh_credential()

        return " ".join([
            self.__token_type,
            self.__access_token,
        ])
