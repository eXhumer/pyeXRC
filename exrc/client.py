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
from random import SystemRandom
from string import ascii_letters, digits
from typing import List

from requests import Session
from requests.utils import default_user_agent

from . import __version__
from .auth import OAuth2Credential
from .exception import RateLimitException


class OAuth2Client:
    resource_base_url = "https://oauth.reddit.com"
    __ratelimit_status = {
        "remaining": None,
        "reset": None,
        "used": None,
    }

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        credential: OAuth2Credential,
        session: Session | None = None,
        user_agent: str = f"{__package__}/{__version__}",
    ):
        if session is None:
            session = Session()

        if session.headers["User-Agent"] == default_user_agent():
            session.headers["User-Agent"] = user_agent

        self.__client_id = client_id
        self.__client_secret = client_secret
        self.__session = session
        self.__credential = credential

    @staticmethod
    def ratelimit_remaining() -> float | None:
        return OAuth2Client.__ratelimit_status["remaining"]

    @staticmethod
    def ratelimit_reset() -> datetime | None:
        return OAuth2Client.__ratelimit_status["reset"]

    @staticmethod
    def ratelimit_used() -> int | None:
        return OAuth2Client.__ratelimit_status["used"]

    def __request(
        self,
        method: str,
        api_endpoint: str,
        **req_opts,
    ):
        while api_endpoint.startswith("/"):
            api_endpoint = api_endpoint[1:]

        if self.__credential.expired:
            self.__credential.refresh(
                self.__session,
                self.__client_id,
                self.__client_secret,
            )

        if "params" in req_opts:
            if "raw_json" not in req_opts["params"]:
                req_opts["params"].update({"raw_json": 1})
        else:
            req_opts["params"] = {"raw_json": 1}

        if "headers" in req_opts:
            if "Authorization" not in req_opts["headers"]:
                req_opts["headers"].update({
                    "Authorization": self.__credential.authorization,
                })
        else:
            req_opts["headers"] = {
                "Authorization": self.__credential.authorization,
            }

        res = self.__session.request(
            method,
            "/".join((
                OAuth2Client.resource_base_url,
                api_endpoint,
            )),
            **req_opts,
        )

        if "X-RateLimit-Remaining" in res.headers:
            OAuth2Client.__ratelimit_status["remaining"] = \
                float(res.headers["X-RateLimit-Remaining"])
        if "X-RateLimit-Reset" in res.headers:
            OAuth2Client.__ratelimit_status["reset"] = \
                datetime.now(tz=timezone.utc) + \
                timedelta(seconds=int(res.headers["X-RateLimit-Reset"]))
        if "X-RateLimit-Used" in res.headers:
            OAuth2Client.__ratelimit_status["used"] = \
                res.headers["X-RateLimit-Used"]

        if OAuth2Client.__ratelimit_status["remaining"] == 0:
            raise RateLimitException(OAuth2Client.__ratelimit_status["reset"])

        return res

    def get(
        self,
        api_endpoint: str,
        **req_opts,
    ):
        return self.__request(
            "GET",
            api_endpoint,
            **req_opts,
        )

    def post(
        self,
        api_endpoint: str,
        **req_opts,
    ):
        return self.__request(
            "POST",
            api_endpoint,
            **req_opts,
        )

    def patch(
        self,
        api_endpoint: str,
        **req_opts,
    ):
        return self.__request(
            "PATCH",
            api_endpoint,
            **req_opts,
        )

    def put(
        self,
        api_endpoint: str,
        **req_opts,
    ):
        return self.__request(
            "PUT",
            api_endpoint,
            **req_opts,
        )

    def options(
        self,
        api_endpoint: str,
        **req_opts,
    ):
        return self.__request(
            "OPTIONS",
            api_endpoint,
            **req_opts,
        )

    def head(
        self,
        api_endpoint: str,
        **req_opts,
    ):
        return self.__request(
            "HEAD",
            api_endpoint,
            **req_opts,
        )

    def delete(
        self,
        api_endpoint: str,
        **req_opts,
    ):
        return self.__request(
            "DELETE",
            api_endpoint,
            **req_opts,
        )

    @property
    def credential(self):
        return self.__credential

    def revoke(self):
        return self.__credential.revoke(
            self.__session,
            self.__client_id,
            self.__client_secret,
        )

    def refresh(self):
        return self.__credential.refresh(
            self.__session,
            self.__client_id,
            self.__client_secret,
        )

    @classmethod
    def password_grant(
        cls,
        client_id: str,
        client_secret: str,
        username: str,
        password: str,
        session: Session | None = None,
        two_factor_code: str | None = None,
        user_agent: str = f"{__package__}/{__version__}",
    ):
        if session is None:
            session = Session()

        if session.headers["User-Agent"] == default_user_agent():
            session.headers["User-Agent"] = user_agent

        return cls(
            client_id,
            client_secret,
            OAuth2Credential.password_grant(
                session,
                client_id,
                client_secret,
                username,
                password,
                two_factor_code=two_factor_code,
                session=session,
            ),
            session=session,
            user_agent=user_agent,
        )

    @classmethod
    def client_credential_grant(
        cls,
        client_id: str,
        client_secret: str,
        session: Session | None = None,
        user_agent: str = f"{__package__}/{__version__}",
    ):
        if session is None:
            session = Session()

        if session.headers["User-Agent"] == default_user_agent():
            session.headers["User-Agent"] = user_agent

        return cls(
            client_id,
            client_secret,
            OAuth2Credential.client_credential_grant(
                client_id,
                client_secret,
                session=session,
            ),
            session=session,
            user_agent=user_agent,
        )

    @classmethod
    def installed_client_grant(
        cls,
        client_id: str,
        client_secret: str,
        device_id: str = "".join([
            SystemRandom().choice(ascii_letters + digits)
            for _ in range(30)
        ]),
        session: Session | None = None,
        user_agent: str = f"{__package__}/{__version__}",
    ):
        if session is None:
            session = Session()

        if session.headers["User-Agent"] == default_user_agent():
            session.headers["User-Agent"] = user_agent

        return cls(
            client_id,
            client_secret,
            OAuth2Credential.installed_client_grant(
                client_id,
                client_secret,
                device_id=device_id,
                session=session,
            ),
            session=session,
            user_agent=user_agent,
        )

    @classmethod
    def authorization_code_grant(
        cls,
        client_id: str,
        client_secret: str,
        authcode: str,
        callback_url: str,
        session: Session | None = None,
        user_agent: str = f"{__package__}/{__version__}",
    ):
        if session is None:
            session = Session()

        if session.headers["User-Agent"] == default_user_agent():
            session.headers["User-Agent"] = user_agent

        return cls(
            client_id,
            client_secret,
            OAuth2Credential.authorization_code_grant(
                client_id,
                client_secret,
                authcode,
                callback_url,
                session=session,
            ),
            session=session,
            user_agent=user_agent,
        )

    @classmethod
    def localserver_code_flow(
        cls,
        client_id: str,
        client_secret: str,
        callback_url: str,
        duration: str,
        scopes: List[str],
        state: str | None = None,
        session: Session | None = None,
        user_agent: str = f"{__package__}/{__version__}",
    ):
        if session is None:
            session = Session()

        if session.headers["User-Agent"] == default_user_agent():
            session.headers["User-Agent"] = user_agent

        return cls(
            client_id,
            client_secret,
            OAuth2Credential.localserver_code_flow(
                client_id,
                client_secret,
                callback_url,
                duration,
                scopes,
                state=state,
                session=session,
            ),
            session=session,
            user_agent=user_agent,
        )

    def comment(self, text: str, thing_id: str):
        return self.post(
            "api/comment",
            data={
                "api_type": "json",
                "return_rtjson": False,  # richtext not supported
                "text": text,
                "thing_id": thing_id,
            },
        )

    def needs_captcha(self):
        return self.get("api/needs_captcha")

    def username_available(self, user: str):
        return self.get("api/username_available", params={"user": user})

    def scopes(self, scopes: str | None):
        params = {}

        if scopes is not None:
            params.update({"scopes": scopes})

        return self.get("api/v1/scopes", params=params)

    def block_user(self, account_id: str, name: str):
        return self.post(
            "api/block_user",
            data={
                "api_type": "json",
                "name": name,
                "account_id": account_id,
            }
        )

    def update_me_prefs(self, **new_me_prefs):
        return self.patch("api/v1/me/prefs", json=new_me_prefs)

    def gold_gild(self, thing_id: str):
        return self.post(f"api/v1/gold/gild/{thing_id}")

    def gold_give(self, months: int, username: str):
        return self.post(
            f"api/v1/gold/give/{username}",
            data={"months": months},
        )

    def delete_thing(self, id: str):
        return self.post("api/del", data={"id": id})

    def editusertext(
        self,
        text: str,
        thing_id: str,
        validate_on_submit: bool = True,
    ):
        return self.post(
            "api/editusertext",
            data={
                "api_type": "json",
                "return_rtjson": False,  # richtext not supported
                "text": text,
                "thing_id": thing_id,
                "validate_on_submit": validate_on_submit,
            })

    def sendreplies(self, thing_id: str, state: bool):
        return self.post(
            "api/sendreplies",
            data={
                "id": thing_id,
                "state": state,
            }
        )

    def link_flair(self, subreddit: str | None = None):
        uri = "api/link_flair"

        if subreddit is not None:
            uri = f"r/{subreddit}/{uri}"

        return self.get(uri)

    def link_flair_v2(self, subreddit: str | None = None):
        uri = "api/link_flair_v2"

        if subreddit is not None:
            uri = f"r/{subreddit}/{uri}"

        return self.get(uri)

    def setflairenabled(
        self,
        flair_enabled: bool,
        subreddit: str | None = None,
    ):
        uri = "api/selectflair"

        if subreddit is not None:
            uri = f"r/{subreddit}/{uri}"

        return self.post(
            uri,
            data={
                "api_type": "json",
                "flair_enabled": flair_enabled,
            },
        )

    def user_flair(self, subreddit: str | None = None):
        uri = "api/user_flair"

        if subreddit is not None:
            uri = f"r/{subreddit}/{uri}"

        return self.get(uri)

    def user_flair_v2(self, subreddit: str | None = None):
        uri = "api/user_flair_v2"

        if subreddit is not None:
            uri = f"r/{subreddit}/{uri}"

        return self.get(uri)

    def me(self):
        return self.get("api/v1/me")

    def get_me_prefs(self, *fields: str):
        return self.get("api/v1/me/prefs", params={"fields": fields})

    def me_throphies(self):
        return self.get("api/v1/me/trophies")
