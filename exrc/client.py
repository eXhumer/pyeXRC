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

from datetime import datetime, timedelta, timezone
from pkg_resources import require
from time import sleep

from requests import Response, Session
from requests.utils import default_user_agent

from .auth import OAuth2Credential


class RedditClient(object):
    __version = require("eXRC")[0].version
    __resource_base_url = "https://oauth.reddit.com"
    __ratelimit_status = {
        "remaining": None,
        "reset": None,
        "used": None,
    }

    def __init__(self, credential: OAuth2Credential) -> None:
        super().__init__()
        self.__session = Session()
        self.__credential = credential

    def __session_ua_check(self, **auth_options: str):
        # Set custom user agent if specified
        if "user_agent" in auth_options:
            self.__session.headers["User-Agent"] = \
                auth_options["user_agent"]

        # default_user_agent is rate limited by reddit to encourage custom
        # user agent
        if self.__session.headers["User-Agent"] == \
                default_user_agent:
            self.__session.headers["User-Agent"] = \
                f"eXRC/{self.__version}"

    @staticmethod
    def ratelimit_remaining() -> float | None:
        return RedditClient.__ratelimit_status["remaining"]

    @staticmethod
    def ratelimit_reset() -> datetime | None:
        return RedditClient.__ratelimit_status["reset"]

    @staticmethod
    def ratelimit_used() -> int | None:
        return RedditClient.__ratelimit_status["used"]

    @staticmethod
    def ratelimit_sleep_until_reset() -> None:
        ratelimit_reset = RedditClient.ratelimit_reset()

        if ratelimit_reset is not None and ratelimit_reset > \
                datetime.now(tz=timezone.utc):
            sleep(
                (datetime.now(tz=timezone.utc) - ratelimit_reset)
                .total_seconds()
            )

    def request(
        self,
        method: str,
        api_endpoint: str,
        **request_opts,
    ) -> Response:
        self.__session_ua_check(**request_opts)

        if not api_endpoint.startswith("/"):
            api_endpoint = f"/{api_endpoint}"

        if "params" in request_opts:
            if "raw_json" not in request_opts["params"]:
                request_opts["params"].update({"raw_json": 1})
        else:
            request_opts["params"] = {"raw_json": 1}

        if "headers" in request_opts:
            if "Authorization" not in request_opts["headers"]:
                request_opts["headers"].update({
                    "Authorization": self.__credential.authorization,
                })
        else:
            request_opts["headers"] = {
                "Authorization": self.__credential.authorization,
            }

        res = self.__session.request(
            method,
            RedditClient.__resource_base_url + api_endpoint,
            **request_opts,
        )

        RedditClient.__ratelimit_status["remaining"] = \
            float(res.headers["X-RateLimit-Remaining"])
        RedditClient.__ratelimit_status["reset"] = \
            datetime.now(tz=timezone.utc) + \
            timedelta(seconds=int(res.headers["X-RateLimit-Reset"]))
        RedditClient.__ratelimit_status["used"] = \
            res.headers["X-RateLimit-Used"]

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
