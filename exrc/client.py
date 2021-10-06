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

from requests import Response, Session

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
        user_agent: str = f"{__package__}/{__version__}",
    ):
        self.__client_id = client_id
        self.__client_secret = client_secret
        self.__session = Session()
        self.__session.headers["User-Agent"] = user_agent
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

    def request(
        self,
        method: str,
        api_endpoint: str,
        **req_opts,
    ) -> Response:
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

        OAuth2Client.__ratelimit_status["remaining"] = \
            float(res.headers["X-RateLimit-Remaining"])
        OAuth2Client.__ratelimit_status["reset"] = \
            datetime.now(tz=timezone.utc) + \
            timedelta(seconds=int(res.headers["X-RateLimit-Reset"]))
        OAuth2Client.__ratelimit_status["used"] = \
            res.headers["X-RateLimit-Used"]

        if OAuth2Client.__ratelimit_status["remaining"] == 0:
            raise RateLimitException(OAuth2Client.__ratelimit_status["reset"])

        return res

    def get(
        self,
        api_endpoint: str,
        **request_opts,
    ) -> Response:
        return self.request(
            "GET",
            api_endpoint,
            **request_opts,
        )

    def post(
        self,
        api_endpoint: str,
        **request_opts,
    ) -> Response:
        return self.request(
            "POST",
            api_endpoint,
            **request_opts,
        )

    def patch(
        self,
        api_endpoint: str,
        **request_opts,
    ) -> Response:
        return self.request(
            "PATCH",
            api_endpoint,
            **request_opts,
        )

    def put(
        self,
        api_endpoint: str,
        **request_opts,
    ) -> Response:
        return self.request(
            "PUT",
            api_endpoint,
            **request_opts,
        )

    def delete(
        self,
        api_endpoint: str,
        **request_opts,
    ) -> Response:
        return self.request(
            "DELETE",
            api_endpoint,
            **request_opts,
        )
