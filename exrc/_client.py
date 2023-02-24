from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from random import choice
from string import ascii_letters, digits
from typing import Literal
from urllib.parse import urlparse
from webbrowser import open as webbrowser_open

from httpx import BasicAuth, Client

from ._const import ACCESS_TOKEN_URL, BASE_URL, OAUTH_URL, REVOKE_TOKEN_URL, USER_AGENT
from ._exception import OAuth2ExpiredTokenException, OAuth2RevokedTokenException, RESTException
from ._type import OAuth2Token, RateLimit
from ._utils import OAuth2WSGICodeFlowExchangeServer

try:
    h2_available = True

except ImportError:
    h2_available = False


class OAuth2Client:
    __CLIENT = Client(http2=h2_available)
    __CLIENT.headers["User-Agent"] = USER_AGENT
    __CLIENT.base_url = OAUTH_URL
    __CLIENT.follow_redirects = True
    __RATE_LIMIT = None

    def __init__(self, client_id: str, token: OAuth2Token, token_issued_at: datetime | None = None,
                 client_secret: str | None = None):
        self.__client_id = client_id
        self.__client_secret = client_secret
        self.__token = token
        self.__token_issued_at = token_issued_at

    def _refresh(self):
        assert "refresh_token" in self.__token

        res = OAuth2Client.__CLIENT.post(f"{BASE_URL}/{ACCESS_TOKEN_URL}",
                                         data={"grant_type": "refresh_token",
                                               "refresh_token": self.__token["refresh_token"]},
                                         auth=BasicAuth(username=self.__client_id,
                                                        password=self.__client_secret or ""))

        if res.status_code >= 400:
            raise RESTException(res)

        token: OAuth2Token = res.json()
        self.__token |= token
        self.__token_issued_at = parsedate_to_datetime(res.headers["Date"])

    def _request(self, method: str, url: str, **kwargs):
        # If we have a token issue date and token is expired
        if self.expired is True:
            # Halt request execution without refresh_token available
            if "refresh_token" not in self.__token:
                raise OAuth2ExpiredTokenException(self.__token, self.expiry)

            self._refresh()

        if "headers" not in kwargs:
            kwargs["headers"] = {"Authorization": self.authorization}

        elif "Authorization" not in kwargs["headers"]:
            kwargs["headers"] |= {"Authorization": self.authorization}

        if "params" not in kwargs:
            kwargs["params"] = {"raw_json": "1"}

        elif "raw_json" not in kwargs["params"]:
            kwargs["params"] |= {"raw_json": "1"}

        res = OAuth2Client.__CLIENT.request(method, url, **kwargs)

        remaining = float(res.headers["X-RateLimit-Remaining"])
        reset = datetime.now(tz=timezone.utc) + \
            timedelta(seconds=int(res.headers["X-RateLimit-Reset"]))
        used = int(res.headers["X-RateLimit-Used"])

        if OAuth2Client.__RATE_LIMIT is None:
            OAuth2Client.__RATE_LIMIT = RateLimit(Remaining=remaining, Reset=reset, Used=used)

        else:
            OAuth2Client.__RATE_LIMIT |= RateLimit(Remaining=remaining, Reset=reset, Used=used)

        if res.status_code >= 400:
            raise RESTException(res)

        return res

    @property
    def authorization(self):
        return f"{self.__token['token_type']} {self.__token['access_token']}"

    @classmethod
    def authorization_code_grant(cls, code: str, client_id: str, redirect_uri: str,
                                 client_secret: str | None = None):
        res = OAuth2Client.__CLIENT.post(f"{BASE_URL}/{ACCESS_TOKEN_URL}",
                                         data={"code": code, "grant_type": "authorization_code",
                                               "redirect_uri": redirect_uri},
                                         auth=BasicAuth(username=client_id,
                                                        password=client_secret or ""))

        if res.status_code >= 400:
            raise RESTException(res)

        token: OAuth2Token = res.json()
        token_issued_at = parsedate_to_datetime(res.headers["Date"])

        return cls(client_id, token, token_issued_at=token_issued_at, client_secret=client_secret)

    @classmethod
    def client_credential_grant(cls, client_id: str, client_secret: str | None = None):
        res = OAuth2Client.__CLIENT.post(f"{BASE_URL}/{ACCESS_TOKEN_URL}",
                                         data={"grant_type": "client_credentials"},
                                         auth=BasicAuth(username=client_id,
                                                        password=client_secret or ""))

        if res.status_code >= 400:
            raise RESTException(res)

        token: OAuth2Token = res.json()
        token_issued_at = parsedate_to_datetime(res.headers["Date"])

        return cls(client_id, token, token_issued_at=token_issued_at, client_secret=client_secret)

    @classmethod
    def code_flow_localserver(cls, client_id: str, redirect_uri: str,
                              duration: Literal["temporary", "permanent"], scopes: list[str],
                              home_endpoint: str = "/", authorize_endpoint: str = "/authorize",
                              state: str | None = None, client_secret: str | None = None):
        netloc = urlparse(redirect_uri).netloc
        netloc_parts = netloc.split(":", maxsplit=1)
        host = netloc_parts[0]
        port = int(netloc_parts[1]) if len(netloc_parts) == 2 else 80

        wsgi_server = OAuth2WSGICodeFlowExchangeServer(host, port, client_id, redirect_uri, scopes,
                                                       duration, home_endpoint=home_endpoint,
                                                       authorize_endpoint=authorize_endpoint,
                                                       state=state)
        wsgi_server.timeout = 1
        webbrowser_open(f"http://{netloc}/")

        while wsgi_server.code is None:
            wsgi_server.handle_request()

        return cls.authorization_code_grant(wsgi_server.code, client_id, redirect_uri,
                                            client_secret=client_secret)

    @property
    def expired(self):
        if not self.expiry:
            return

        return datetime.now(tz=timezone.utc) > self.expiry

    @property
    def expiry(self):
        if not self.__token_issued_at:
            return

        return self.__token_issued_at + timedelta(seconds=self.__token["expires_in"])

    @classmethod
    def installed_client_grant(cls, client_id: str, device_id: str | None = None,
                               client_secret: str | None = None):
        device_id = device_id or "".join([choice(ascii_letters + digits) for _ in range(30)])

        res = OAuth2Client.__CLIENT.post(f"{BASE_URL}/{ACCESS_TOKEN_URL}", data={
            "grant_type": "https://oauth.reddit.com/grants/installed_client",
            "device_id": device_id},
                                         auth=BasicAuth(username=client_id,
                                                        password=client_secret or ""))

        if res.status_code >= 400:
            raise RESTException(res)

        token: OAuth2Token = res.json()
        token_issued_at = parsedate_to_datetime(res.headers["Date"])

        return cls(client_id, token, token_issued_at=token_issued_at, client_secret=client_secret)

    @classmethod
    def password_grant(cls, client_id: str, username: str, password: str,
                       two_factor_code: str | None = None, client_secret: str | None = None):
        if two_factor_code is not None:
            if not (len(two_factor_code) == 6 and two_factor_code.isnumeric()):
                raise ValueError("Invalid two factor code! Must be of length" +
                                 " 6 and must be numeric!")

            password = f"{password}:{two_factor_code}"

        res = OAuth2Client.__CLIENT.post(f"{BASE_URL}/{ACCESS_TOKEN_URL}",
                                         data={"grant_type": "password", "username": username,
                                               "password": password},
                                         auth=BasicAuth(username=client_id,
                                                        password=client_secret or ""))

        if res.status_code >= 400:
            raise RESTException(res)

        token: OAuth2Token = res.json()
        token_issued_at = parsedate_to_datetime(res.headers["Date"])

        return cls(client_id, token, token_issued_at=token_issued_at, client_secret=client_secret)

    def revoke(self):
        if "refresh_token" in self.__token:
            data = {"token": self.__token["refresh_token"], "token_type_hint": "refresh_token"}

        else:
            data = {"token": self.__token["access_token"], "token_type_hint": "access_token"}

        res = self.__client.post(f"{BASE_URL}/{REVOKE_TOKEN_URL}", data=data,
                                 auth=BasicAuth(username=self.__client_id,
                                                password=self.__client_secret or ""))

        if res.status_code >= 400:
            raise RESTException(res)

        raise OAuth2RevokedTokenException(self.__token)
