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
from json import dumps, loads
from mimetypes import guess_type
from pathlib import Path
from random import SystemRandom
from string import ascii_letters, digits
from typing import Any, Dict, List

from requests import Session
from requests.utils import default_user_agent
from requests_toolbelt import MultipartEncoder
from websocket import create_connection

from . import __version__
from .auth import OAuth2Credential
from .exception import (
    MediaUploadException,
    RateLimitException,
    ResponseException,
)


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
        params = None

        if len(fields) > 0:
            params = {"fields": fields}

        return self.get("api/v1/me/prefs", params=params)

    def me_throphies(self):
        return self.get("api/v1/me/trophies")

    def submit_poll(
        self,
        title: str,
        selftext: str,
        options: List[str],
        duration: int,
        subreddit: str | None = None,
        flair_id: str | None = None,
        flair_text: str | None = None,
        resubmit: bool = True,
        send_replies: bool = False,
        nsfw: bool = False,
        spoiler: bool = False,
        validate_on_submit: bool = True,
        collection_id: str | None = None,
        discussion_type: str | None = None,
        event_end: str | None = None,
        event_start: str | None = None,
        event_tz: str | None = None,
        g_recaptcha_response: str | None = None,
    ):
        if subreddit is None:
            res = self.me()

            if res.status_code != 200:
                return res

            me_name = res.json()["name"]
            subreddit = f"u_{me_name}"

        data = {
            "sr": subreddit,
            "text": selftext,
            "options": options,
            "duration": duration,
            "resubmit": resubmit,
            "sendreplies": send_replies,
            "title": title,
            "nsfw": nsfw,
            "spoiler": spoiler,
            "validate_on_submit": validate_on_submit,
        }

        for key, value in (
            ("flair_id", flair_id),
            ("flair_text", flair_text),
            ("collection_id", collection_id),
            ("discussion_type", discussion_type),
            ("event_end", event_end),
            ("event_start", event_start),
            ("event_tz", event_tz),
            ("g-recaptcha-response", g_recaptcha_response),
        ):
            if value is not None:
                data[key] = value

        return self.post("api/submit_poll_post", json=data)

    def __submit(
        self,
        kind: str,
        title: str,
        text: str | None = None,
        url: str | None = None,
        video_poster_url: str | None = None,
        nsfw: bool = False,
        resubmit: bool = True,
        send_replies: bool = False,
        spoiler: bool = False,
        subreddit: str | None = None,
        validate_on_submit: bool = True,
        collection_id: str | None = None,
        flair_id: str | None = None,
        flair_text: str | None = None,
        discussion_type: str | None = None,
        event_end: str | None = None,
        event_start: str | None = None,
        event_tz: str | None = None,
        g_recaptcha_response: str | None = None,
        richtext_json: Dict[str, Any] | None = None,
    ):
        if subreddit is None:
            res = self.me()

            if res.status_code != 200:
                return res

            me_name = res.json()["name"]
            subreddit = f"u_{me_name}"

        data = {
            "api_type": "json",
            "nsfw": nsfw,
            "resubmit": resubmit,
            "sendreplies": send_replies,
            "spoiler": spoiler,
            "sr": subreddit,
            "title": title,
            "kind": kind,
            "validate_on_submit": validate_on_submit,
        }

        for key, value in (
            ("flair_id", flair_id),
            ("flair_text", flair_text),
            ("collection_id", collection_id),
            ("discussion_type", discussion_type),
            ("event_end", event_end),
            ("event_start", event_start),
            ("event_tz", event_tz),
            ("g-recaptcha-response", g_recaptcha_response),
            ("video_poster_url", video_poster_url),
            ("text", text),
            ("url", url),
            ("richtext_json", richtext_json),
        ):
            if value is not None:
                data[key] = value

        return self.post(
            "api/submit",
            data=data,
        )

    def submit_text(
        self,
        title: str,
        text: str,
        nsfw: bool = False,
        resubmit: bool = True,
        send_replies: bool = False,
        spoiler: bool = False,
        subreddit: str | None = None,
        collection_id: str | None = None,
        flair_id: str | None = None,
        flair_text: str | None = None,
        discussion_type: str | None = None,
        event_end: str | None = None,
        event_start: str | None = None,
        event_tz: str | None = None,
        g_recaptcha_response: str | None = None,
        convert_to_richtext: bool = False,
    ):
        rt_json = None

        if convert_to_richtext is True:
            res = self.__convert_rte_body(text)
            rt_json = dumps(res.json()["output"])
            print(rt_json)
            text = None

        return self.__submit(
            "self",
            title,
            text=text,
            nsfw=nsfw,
            resubmit=resubmit,
            send_replies=send_replies,
            spoiler=spoiler,
            subreddit=subreddit,
            collection_id=collection_id,
            flair_id=flair_id,
            flair_text=flair_text,
            discussion_type=discussion_type,
            event_end=event_end,
            event_start=event_start,
            event_tz=event_tz,
            g_recaptcha_response=g_recaptcha_response,
            richtext_json=rt_json,
        )

    def __upload_media(
        self,
        media_path: Path,
        upload_type: str = "link",
    ):
        mimetype = guess_type(media_path.name)[0]

        res = self.post(
            "api/media/asset",
            data={
                "filepath": media_path.name,
                "mimetype": guess_type(media_path.name)[0],
            },
        )

        if res.status_code != 200:
            raise ResponseException(
                res,
                "ERROR: Invalid status code while requesting media lease!",
            )

        action: str = res.json()["args"]["action"]
        fields: Dict[str, Any] = {
            item["name"]: item["value"]
            for item
            in res.json()["args"]["fields"]
        }
        websocket_url: str = res.json()["asset"]["websocket_url"]
        asset_id: str = res.json()["asset"]["asset_id"]

        fields.update({
            "file": (
                media_path.name,
                media_path.open(mode="rb"),
                mimetype,
            )
        })

        mp_data = MultipartEncoder(fields=fields)

        res = self.__session.post(
            f"https:{action}",
            data=mp_data,
            headers={"Content-Type": mp_data.content_type},
        )

        if res.status_code != 201:
            raise ResponseException(
                res,
                "ERROR: Invalid status code while uploading media!",
            )

        return (
            f"https:{action}/{fields['key']}"
            if upload_type == "link"
            else asset_id
        ), websocket_url

    def __submit_media(
        self,
        kind: str,
        title: str,
        media_path: Path,
        nsfw: bool = False,
        resubmit: bool = True,
        send_replies: bool = False,
        spoiler: bool = False,
        validate_on_submit: bool = True,
        subreddit: str | None = None,
        collection_id: str | None = None,
        flair_id: str | None = None,
        flair_text: str | None = None,
        discussion_type: str | None = None,
        event_end: str | None = None,
        event_start: str | None = None,
        event_tz: str | None = None,
        video_poster_url: str | None = None,
        g_recaptcha_response: str | None = None,
    ):
        if kind not in ["image", "video", "videogif"]:
            raise ValueError("Invalid media kind!")

        media_url, ws_url = self.__upload_media(media_path)

        self.__submit(
            kind,
            title,
            url=media_url,
            nsfw=nsfw,
            resubmit=resubmit,
            send_replies=send_replies,
            spoiler=spoiler,
            validate_on_submit=validate_on_submit,
            subreddit=subreddit,
            collection_id=collection_id,
            flair_id=flair_id,
            flair_text=flair_text,
            discussion_type=discussion_type,
            event_end=event_end,
            event_start=event_start,
            event_tz=event_tz,
            video_poster_url=video_poster_url,
            g_recaptcha_response=g_recaptcha_response,
        )

        ws_conn = create_connection(ws_url)
        ws_update = loads(ws_conn.recv())
        ws_conn.close()

        if ws_update["type"] == "failed":
            raise MediaUploadException

        return ws_update

    def submit_image(
        self,
        title: str,
        image_path: Path,
        nsfw: bool = False,
        resubmit: bool = True,
        send_replies: bool = False,
        spoiler: bool = False,
        validate_on_submit: bool = True,
        subreddit: str | None = None,
        collection_id: str | None = None,
        flair_id: str | None = None,
        flair_text: str | None = None,
        discussion_type: str | None = None,
        event_end: str | None = None,
        event_start: str | None = None,
        event_tz: str | None = None,
        g_recaptcha_response: str | None = None,
    ):
        return self.__submit_media(
            "image",
            title,
            image_path,
            nsfw=nsfw,
            resubmit=resubmit,
            send_replies=send_replies,
            spoiler=spoiler,
            validate_on_submit=validate_on_submit,
            subreddit=subreddit,
            collection_id=collection_id,
            flair_id=flair_id,
            flair_text=flair_text,
            discussion_type=discussion_type,
            event_end=event_end,
            event_start=event_start,
            event_tz=event_tz,
            g_recaptcha_response=g_recaptcha_response,
        )

    def submit_video(
        self,
        title: str,
        video_path: Path,
        videogif: bool = False,
        thumbnail_image_path: Path | None = None,
        nsfw: bool = False,
        resubmit: bool = True,
        send_replies: bool = False,
        spoiler: bool = False,
        validate_on_submit: bool = True,
        subreddit: str | None = None,
        collection_id: str | None = None,
        flair_id: str | None = None,
        flair_text: str | None = None,
        discussion_type: str | None = None,
        event_end: str | None = None,
        event_start: str | None = None,
        event_tz: str | None = None,
        g_recaptcha_response: str | None = None,
    ):
        return self.__submit_media(
            "videogif" if videogif else "video",
            title,
            video_path,
            nsfw=nsfw,
            resubmit=resubmit,
            send_replies=send_replies,
            spoiler=spoiler,
            validate_on_submit=validate_on_submit,
            subreddit=subreddit,
            collection_id=collection_id,
            flair_id=flair_id,
            flair_text=flair_text,
            discussion_type=discussion_type,
            event_end=event_end,
            event_start=event_start,
            event_tz=event_tz,
            video_poster_url=(
                self.__upload_media(thumbnail_image_path)[0]
                if thumbnail_image_path is not None
                else None
            ),
            g_recaptcha_response=g_recaptcha_response,
        )

    def upload_inline_media(self, media_path: Path):
        return self.__upload_media(media_path, upload_type="selfpost")[0]

    def submit_gallery(
        self,
        title: str,
        images: Dict[Path, Dict[str, str]],
        nsfw: bool = False,
        send_replies: bool = False,
        spoiler: bool = False,
        validate_on_submit: bool = True,
        subreddit: str | None = None,
        collection_id: str | None = None,
        flair_id: str | None = None,
        flair_text: str | None = None,
        discussion_type: str | None = None,
        event_end: str | None = None,
        event_start: str | None = None,
        event_tz: str | None = None,
        g_recaptcha_response: str | None = None,
    ):
        if subreddit is None:
            res = self.me()

            if res.status_code != 200:
                return res

            me_name = res.json()["name"]
            subreddit = f"u_{me_name}"

        data = {
            "api_type": "json",
            "items": [],
            "nsfw": nsfw,
            "sendreplies": send_replies,
            "show_error_list": True,
            "spoiler": spoiler,
            "sr": subreddit,
            "title": title,
            "validate_on_submit": validate_on_submit,
        }

        for key, value in (
            ("flair_id", flair_id),
            ("flair_text", flair_text),
            ("collection_id", collection_id),
            ("discussion_type", discussion_type),
            ("event_end", event_end),
            ("event_start", event_start),
            ("event_tz", event_tz),
            ("g_recaptcha_response", g_recaptcha_response),
        ):
            if value is not None:
                data[key] = value

        for img_path, img_data in images.items():
            data["items"].append(
                {
                    "caption": img_data.get("caption", ""),
                    "outbound_url": img_data.get("outbound_url", ""),
                    "media_id": self.__upload_media(
                        img_path,
                        upload_type="gallery",
                    )[0],
                }
            )

        return self.post("api/submit_gallery_post", json=data)

    def __convert_rte_body(self, md_text: str):
        return self.post(
            "api/convert_rte_body_format",
            data={
                "output_mode": "rtjson",
                "markdown_text": md_text,
            }
        )
