# pyeXRC - Python Reddit Client
# Copyright (C) 2021-2022 eXhumer

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3 of the License.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

from contextlib import closing
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from io import BytesIO
from json import dumps, loads
from mimetypes import guess_type
from pathlib import Path
from pkg_resources import require, resource_stream
from random import choice
from string import ascii_letters, digits
from typing import Any, Dict, IO, List, Literal, Tuple, TypedDict
from urllib.parse import urlparse
from webbrowser import open as webbrowser_open
from wsgiref.simple_server import make_server
from xml.etree.ElementTree import parse as xml_parse

from requests import Session
from requests.auth import HTTPBasicAuth
from requests.utils import default_user_agent as requests_user_agent
from requests_toolbelt import MultipartEncoder
from websocket import create_connection

from ._model import RedditClientCredential, RedditConvertRTE, RedditMe, RedditMediaAsset, \
    RedditMediaSubmission, RedditMediaUploadUpdate, RedditOAuth2Token, RedditScopesV1, \
    RedditSubmission
from ._utils import NoLoggingWSGIRequestHandler, OAuth2WSGICodeFlowExchangeApp

__version__ = require(__package__)[0].version
__user_agent__ = f"Python:pyeXRC:v{__version__} (by /u/ContentPuff)"
default_user_agent = f"{__package__}/{__version__}"
default_video_poster = resource_stream(__name__, "default_video_poster.png")


class RedditGalleryImage(TypedDict):
    caption: str
    outbound_url: str
    media_id: str


class RedditRateLimit(TypedDict):
    Remaining: float
    Reset: datetime
    Used: int


class RedditOAuth2Client:
    ACCESS_TOKEN_V1 = "api/v1/access_token"
    AUTHORIZE_V1 = "api/v1/authorize"
    BASE_URL = "https://www.reddit.com"
    OAUTH_URL = "https://oauth.reddit.com"
    REVOKE_TOKEN_V1 = "api/v1/revoke_token"
    SCOPES_V1 = "api/v1/scopes"
    __RATE_LIMIT: RedditRateLimit | None = None
    __SESSION = Session()
    __SESSION.headers["User-Agent"] = __user_agent__

    def __init__(self, client_id: str, token: RedditOAuth2Token, client_secret: str | None = None,
                 session: Session | None = None, token_issued_at: datetime | None = None):
        self.__client_id = client_id
        self.__client_secret = client_secret
        self.__session = session or RedditOAuth2Client.__SESSION
        self.__token = token
        self.__token_issued_at = token_issued_at

        if "User-Agent" not in self.__session.headers or \
                self.__session.headers["User-Agent"] == requests_user_agent():
            self.__session.headers["User-Agent"] = __user_agent__

    def __convert_rte_body(self, md_text: str):
        return self.__request("POST", "api/convert_rte_body_format",
                              data={"output_mode": "rtjson", "markdown_text": md_text})

    def __request(self, method: str, endpoint: str, params: Dict[str, str] = None,
                  headers: Dict[str, str] = None, json: Dict[str, Any] = None,
                  data: Any | None = None):
        while endpoint.startswith("/"):
            endpoint = endpoint[1:]

        if not self.__token_issued_at and "refresh_token" in self.__token:
            self.refresh()

        if self.expired is True:
            if "refresh_token" not in self.__token:
                raise RuntimeError("refresh_token not available! Unable to continue!")

            self.refresh()

        if params is not None:
            if "raw_json" not in params:
                params |= {"raw_json": 1}

        else:
            params = {"raw_json": 1}

        if headers is not None:
            if "Authorization" not in headers:
                headers |= {"Authorization": self.authorization}

        else:
            headers = {"Authorization": self.authorization}

        r = self.__session.request(method, f"{RedditOAuth2Client.OAUTH_URL}/{endpoint}",
                                   params=params, headers=headers, json=json, data=data)
        r.raise_for_status()

        remaining = float(r.headers["X-RateLimit-Remaining"])
        reset = datetime.now(tz=timezone.utc) + \
            timedelta(seconds=int(r.headers["X-RateLimit-Reset"]))
        used = int(r.headers["X-RateLimit-Used"])

        if RedditOAuth2Client.__RATE_LIMIT is None:
            RedditOAuth2Client.__RATE_LIMIT = RedditRateLimit(Remaining=remaining, Reset=reset,
                                                              Used=used)

        else:
            RedditOAuth2Client.__RATE_LIMIT |= RedditRateLimit(Remaining=remaining, Reset=reset,
                                                               Used=used)

        if RedditOAuth2Client.__RATE_LIMIT["Remaining"] == 0:
            raise RuntimeError(f"Rate limited until {str(reset)}!")

        return r

    def __submit(self, kind: str, title: str, text: str | None = None, url: str | None = None,
                 video_poster_url: str | None = None, nsfw: bool = False, resubmit: bool = True,
                 send_replies: bool = False, spoiler: bool = False, subreddit: str | None = None,
                 validate_on_submit: bool = True, collection_id: str | None = None,
                 flair_id: str | None = None, flair_text: str | None = None,
                 discussion_type: str | None = None, event_end: str | None = None,
                 event_start: str | None = None, event_tz: str | None = None,
                 g_recaptcha_response: str | None = None,
                 richtext_json: Dict[str, Any] | None = None):
        data = {"api_type": "json", "nsfw": nsfw, "resubmit": resubmit,
                "sendreplies": send_replies, "spoiler": spoiler,
                "sr": subreddit or self.me["subreddit"]["display_name"], "title": title,
                "kind": kind, "validate_on_submit": validate_on_submit}

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

        return self.__request("POST", "api/submit", data=data)

    def __submit_media(self, kind: str, title: str, media_io: IO[bytes], media_filename: str,
                       nsfw: bool = False, resubmit: bool = True, send_replies: bool = False,
                       spoiler: bool = False, validate_on_submit: bool = True,
                       subreddit: str | None = None, collection_id: str | None = None,
                       flair_id: str | None = None, flair_text: str | None = None,
                       discussion_type: str | None = None, event_end: str | None = None,
                       event_start: str | None = None, event_tz: str | None = None,
                       video_poster_url: str | None = None,
                       g_recaptcha_response: str | None = None):
        if kind not in ["image", "video", "videogif"]:
            raise ValueError("Invalid media kind!")

        if kind in ["video", "videogif"]:
            assert video_poster_url is not None

        media_url, asset_id, upload_data = self.__upload_media(media_io, media_filename)

        r = self.__submit(kind, title, url=media_url, nsfw=nsfw, resubmit=resubmit,
                          send_replies=send_replies, spoiler=spoiler,
                          validate_on_submit=validate_on_submit, subreddit=subreddit,
                          collection_id=collection_id, flair_id=flair_id, flair_text=flair_text,
                          discussion_type=discussion_type, event_end=event_end,
                          event_start=event_start, event_tz=event_tz,
                          video_poster_url=video_poster_url,
                          g_recaptcha_response=g_recaptcha_response)
        r.raise_for_status()

        submission: RedditMediaSubmission = r.json()
        ws_url = submission["json"]["data"]["websocket_url"]

        with closing(create_connection(ws_url)) as ws:
            ws_update: RedditMediaUploadUpdate = loads(ws.recv())

        if ws_update["type"] == "failed":
            raise RuntimeError(ws_update)

        if kind == "image":
            post_url = f"https://i.redd.it/{asset_id}{Path(media_filename).suffix}"

        else:
            post_url = f"https://v.redd.it/{asset_id}"

        return upload_data, ws_update, post_url

    def __upload_media(self, media_stream: IO[bytes], media_filename: str):
        mimetype = guess_type(media_filename)[0]

        r = self.__request("POST", "api/media/asset", data={"filepath": media_filename,
                                                            "mimetype": mimetype})
        r.raise_for_status()
        media_asset: RedditMediaAsset = r.json()

        action = media_asset["args"]["action"]
        fields = {item["name"]: item["value"] for item in media_asset["args"]["fields"]}
        asset_id = media_asset["asset"]["asset_id"]

        fields.update({"file": (media_filename, media_stream, mimetype)})

        mp_data = MultipartEncoder(fields=fields)

        r = self.__session.post(f"https:{action}", data=mp_data,
                                headers={"Content-Type": mp_data.content_type})
        r.raise_for_status()

        action_xml = xml_parse(BytesIO(r.content))
        post_response = action_xml.getroot()

        upload_data: Dict[str, str] = {}

        for element in post_response:
            upload_data |= {element.tag: element.text}

        return f"https:{action}/{fields['key']}", asset_id, upload_data

    @property
    def authorization(self):
        return f"{self.__token['token_type']} {self.__token['access_token']}"

    @classmethod
    def authorization_code_grant(cls, code: str, client_id: str, redirect_uri: str,
                                 client_secret: str | None = None, session: Session | None = None):
        session = session or RedditOAuth2Client.__SESSION

        if "User-Agent" not in session.headers or \
                session.headers["User-Agent"] == requests_user_agent():
            session.headers["User-Agent"] = __user_agent__

        r = session.post(f"{RedditOAuth2Client.BASE_URL}/{RedditOAuth2Client.ACCESS_TOKEN_V1}",
                         data={"code": code, "grant_type": "authorization_code",
                               "redirect_uri": redirect_uri},
                         auth=HTTPBasicAuth(client_id, client_secret or ""))

        r.raise_for_status()

        token: RedditOAuth2Token = r.json()
        token_issued_at = parsedate_to_datetime(r.headers["Date"])

        return cls(client_id, token, session=session, client_secret=client_secret,
                   token_issued_at=token_issued_at)

    @property
    def client_credential(self):
        cc = RedditClientCredential(client_id=self.__client_id)

        if self.__client_secret:
            cc |= {"client_secret": self.__client_secret}

        return cc

    @classmethod
    def client_credential_grant(cls, client_id: str, client_secret: str,
                                session: Session | None = None):
        session = session or RedditOAuth2Client.__SESSION

        if "User-Agent" not in session.headers or \
                session.headers["User-Agent"] == requests_user_agent():
            session.headers["User-Agent"] = __user_agent__

        r = session.post(
            f"{RedditOAuth2Client.BASE_URL}/{RedditOAuth2Client.ACCESS_TOKEN_V1}",
            data={"grant_type": "client_credentials"},
            auth=HTTPBasicAuth(client_id, client_secret or ""))
        r.raise_for_status()

        token: RedditOAuth2Token = r.json()
        token_issued_at = parsedate_to_datetime(r.headers["Date"])

        return cls(client_id, token, session=session, client_secret=client_secret,
                   token_issued_at=token_issued_at)

    @classmethod
    def code_flow_localserver(cls, client_id: str, redirect_uri: str,
                              duration: Literal["temporary", "permanent"], scopes: List[str],
                              client_secret: str | None = None, state: str | None = None,
                              session: Session | None = None):
        netloc = urlparse(redirect_uri).netloc
        netloc_parts = netloc.split(":", maxsplit=1)
        host = netloc_parts[0]
        port = int(netloc_parts[1]) if len(netloc_parts) == 2 else 80

        wsgi_app = OAuth2WSGICodeFlowExchangeApp(client_id, redirect_uri, scopes, duration,
                                                 state=state)
        wsgi_server = make_server(host, port, wsgi_app, handler_class=NoLoggingWSGIRequestHandler)

        webbrowser_open(f"http://{netloc}/")

        while wsgi_app.code is None:
            wsgi_server.handle_request()

        session = session or RedditOAuth2Client.__SESSION

        if "User-Agent" not in session.headers or \
                session.headers["User-Agent"] == requests_user_agent():
            session.headers["User-Agent"] = __user_agent__

        return cls.authorization_code_grant(wsgi_app.code, client_id, redirect_uri,
                                            client_secret=client_secret, session=session)

    def comment(self, text: str, thing_id: str):
        return self.__request("POST", "api/comment", data={"api_type": "json",
                                                           "return_rtjson": False,
                                                           "text": text,
                                                           "thing_id": thing_id})

    def comments(self, post_id: str, sort: str = "confidence", subreddit: str | None = None,
                 comment: str | None = None, context: int | None = None, depth: int | None = None,
                 limit: int | None = None, showedits: bool | None = None,
                 showmedia: bool | None = None, showmore: bool | None = None,
                 showtitle: bool | None = None, threaded: bool | None = None,
                 truncate: int | None = None):
        params = {"sort": sort}

        for key, value in (
            ("comment", comment),
            ("context", context),
            ("depth", depth),
            ("limit", limit),
            ("showedits", showedits),
            ("showmedia", showmedia),
            ("showmore", showmore),
            ("showtitle", showtitle),
            ("threaded", threaded),
            ("truncate", truncate),
        ):
            if value is not None:
                params[key] = value

        if subreddit is not None:
            return self.__request("GET", f"comments/{post_id}", params=params)

        return self.__request("GET", f"r/{subreddit}/comments/{post_id}", params=params)

    def delete_thing(self, id: str):
        return self.__request("POST", "api/del", data={"id": id})

    def editusertext(self, text: str, thing_id: str, validate: bool = True):
        return self.__request("POST", "api/editusertext", data={"api_type": "json",
                                                                "return_rtjson": False,
                                                                "text": text,
                                                                "thing_id": thing_id,
                                                                "validate_on_submit": validate})

    @property
    def expired(self):
        if not self.__token_issued_at:
            return None

        assert self.expires_at is not None
        return datetime.now(tz=timezone.utc) >= self.expires_at

    @property
    def expires_at(self):
        if not self.__token_issued_at:
            return None

        return self.__token_issued_at + timedelta(seconds=self.__token["expires_in"])

    def info(self, ids: List[str] | None = None, sr_names: List[str] | None = None,
             url: str | None = None, subreddit: str | None = None):
        params = None

        if ids is not None or sr_names is not None or url is not None:
            params = {}

            if ids is not None:
                params |= {"id": ",".join(ids)}

            if sr_names is not None:
                params |= {"sr_name": ",".join(sr_names)}

            if url is not None:
                params |= {"url": url}

        if subreddit is not None:
            return self.__request("GET", f"r/{subreddit}/api/info", params=params)

        return self.__request("GET", "api/info", params=params)

    @classmethod
    def installed_client_grant(cls, client_id: str, client_secret: str | None = None,
                               device_id: str | None = None, session: Session | None = None):
        device_id = device_id or "".join([choice(ascii_letters + digits) for _ in range(30)])
        session = session or RedditOAuth2Client.__SESSION

        if "User-Agent" not in session.headers or \
                session.headers["User-Agent"] == requests_user_agent():
            session.headers["User-Agent"] = __user_agent__

        r = session.post(
            f"{RedditOAuth2Client.BASE_URL}/{RedditOAuth2Client.ACCESS_TOKEN_V1}",
            data={
                "grant_type": "https://oauth.reddit.com/grants/installed_client",
                "device_id": device_id,
            },
            auth=HTTPBasicAuth(client_id, client_secret or ""),
        )
        r.raise_for_status()

        token: RedditOAuth2Token = r.json()
        token_issued_at = parsedate_to_datetime(r.headers["Date"])

        return cls(client_id, token, session=session, client_secret=client_secret,
                   token_issued_at=token_issued_at)

    @property
    def me(self):
        r = self.__request("GET", "api/v1/me")
        r.raise_for_status()

        me: RedditMe = r.json()
        return me

    @classmethod
    def password_grant(cls, username: str, password: str, client_id: str,
                       two_factor_code: str | None = None, client_secret: str | None = None,
                       session: Session | None = None):
        if two_factor_code is not None:
            if not (len(two_factor_code) == 6 and two_factor_code.isnumeric()):
                raise ValueError("Invalid two factor code! Must be of length" +
                                 " 6 and must be numeric!")

            password = f"{password}:{two_factor_code}"

        session = session or RedditOAuth2Client.__SESSION

        if "User-Agent" not in session.headers or \
                session.headers["User-Agent"] == requests_user_agent():
            session.headers["User-Agent"] = __user_agent__

        r = session.post(
            f"{RedditOAuth2Client.BASE_URL}/{RedditOAuth2Client.ACCESS_TOKEN_V1}",
            data={"grant_type": "password", "username": username, "password": password},
            auth=HTTPBasicAuth(client_id, client_secret or ""),
        )
        r.raise_for_status()

        token: RedditOAuth2Token = r.json()
        token_issued_at = parsedate_to_datetime(r.headers["Date"])

        return cls(client_id, token, session=session, client_secret=client_secret,
                   token_issued_at=token_issued_at)

    def posts(self, subreddit: str | None = None,
              sort: Literal["best", "controversial", "new", "random", "rising", "top"] = "best",
              before: str | None = None, limit: int | None = None):
        params = {}

        if before:
            params |= {"before": before}

        if limit:
            params |= {"limit": limit}

        return self.__request("GET", f"r/{subreddit}/{sort}" if subreddit else sort, params=params)

    def refresh(self):
        if "refresh_token" not in self.__token:
            raise KeyError("Attempting to refresh without refresh_token available!")

        r = self.__session.post(
            f"{RedditOAuth2Client.BASE_URL}/{RedditOAuth2Client.ACCESS_TOKEN_V1}",
            data={"grant_type": "refresh_token", "refresh_token": self.__token["refresh_token"]},
            auth=HTTPBasicAuth(self.__client_id, self.__client_secret or ""),
        )
        r.raise_for_status()

        token: RedditOAuth2Token = r.json()
        self.__token_issued_at = parsedate_to_datetime(r.headers["Date"])
        self.__token |= token

    def revoke(self):
        if "refresh_token" in self.__token:
            r = self.__session.post(
                f"{RedditOAuth2Client.BASE_URL}/{RedditOAuth2Client.REVOKE_TOKEN_V1}",
                data={"token": self.__token["refresh_token"], "token_type_hint": "refresh_token"},
                auth=HTTPBasicAuth(self.__client_id, self.__client_secret or ""),
            )

        else:
            r = self.__session.post(
                f"{RedditOAuth2Client.BASE_URL}/{RedditOAuth2Client.REVOKE_TOKEN_V1}",
                data={"token": self.__token["access_token"], "token_type_hint": "access_token"},
                auth=HTTPBasicAuth(self.__client_id, self.__client_secret or ""),
            )

        r.raise_for_status()

    def sendreplies(self, thing_id: str, state: bool):
        return self.__request("POST", "api/sendreplies", data={"id": thing_id, "state": state})

    @staticmethod
    def scopes_v1(session: Session | None = None):
        session = session or RedditOAuth2Client.__SESSION

        if "User-Agent" not in session.headers or \
                session.headers["User-Agent"] == requests_user_agent():
            session.headers["User-Agent"] = __user_agent__

        r = session.get(f"{RedditOAuth2Client.BASE_URL}/{RedditOAuth2Client.SCOPES_V1}")
        r.raise_for_status()

        scopes: RedditScopesV1 = r.json()
        return scopes

    def submit_gallery(self, title: str,
                       images: List[Tuple[IO[bytes], str, str | None, str | None]],
                       nsfw: bool = False, send_replies: bool = False, spoiler: bool = False,
                       validate_on_submit: bool = True, subreddit: str | None = None,
                       collection_id: str | None = None, flair_id: str | None = None,
                       flair_text: str | None = None, discussion_type: str | None = None,
                       event_end: str | None = None, event_start: str | None = None,
                       event_tz: str | None = None, g_recaptcha_response: str | None = None):
        data = {
            "api_type": "json",
            "nsfw": nsfw,
            "sendreplies": send_replies,
            "show_error_list": True,
            "spoiler": spoiler,
            "sr": subreddit or self.me["subreddit"]["display_name"],
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

        items: List[RedditGalleryImage] = []

        for image_io, image_filename, caption, outbound_url in images:
            media_id = self.__upload_media(image_io, image_filename)[1]
            items.append(RedditGalleryImage(caption=caption or "",
                                            outbound_url=outbound_url or "", media_id=media_id))

        data |= {"items": items}

        return self.__request("POST", "api/submit_gallery_post", json=data)

    def submit_image(self, title: str, image_io: IO[bytes], image_filename: str,
                     nsfw: bool = False, resubmit: bool = True, send_replies: bool = False,
                     spoiler: bool = False, validate_on_submit: bool = True,
                     subreddit: str | None = None, collection_id: str | None = None,
                     flair_id: str | None = None, flair_text: str | None = None,
                     discussion_type: str | None = None, event_end: str | None = None,
                     event_start: str | None = None, event_tz: str | None = None,
                     g_recaptcha_response: str | None = None):
        return self.__submit_media("image", title, image_io, image_filename, nsfw=nsfw,
                                   resubmit=resubmit, send_replies=send_replies, spoiler=spoiler,
                                   validate_on_submit=validate_on_submit, subreddit=subreddit,
                                   collection_id=collection_id, flair_id=flair_id,
                                   flair_text=flair_text, discussion_type=discussion_type,
                                   event_end=event_end, event_start=event_start, event_tz=event_tz,
                                   g_recaptcha_response=g_recaptcha_response)

    def submit_link(self, title: str, url: str, nsfw: bool = False, resubmit: bool = True,
                    send_replies: bool = False, spoiler: bool = False,
                    subreddit: str | None = None, collection_id: str | None = None,
                    flair_id: str | None = None, flair_text: str | None = None,
                    discussion_type: str | None = None, event_end: str | None = None,
                    event_start: str | None = None, event_tz: str | None = None,
                    g_recaptcha_response: str | None = None):
        r = self.__submit("link", title, url=url, nsfw=nsfw, resubmit=resubmit,
                          send_replies=send_replies, spoiler=spoiler, subreddit=subreddit,
                          collection_id=collection_id, flair_id=flair_id, flair_text=flair_text,
                          discussion_type=discussion_type, event_end=event_end,
                          event_start=event_start, event_tz=event_tz,
                          g_recaptcha_response=g_recaptcha_response)
        r.raise_for_status()

        data: RedditSubmission = r.json()
        return data

    def submit_poll(self, title: str, selftext: str, options: List[str], duration: int,
                    subreddit: str | None = None, flair_id: str | None = None,
                    flair_text: str | None = None, resubmit: bool = True,
                    send_replies: bool = False, nsfw: bool = False, spoiler: bool = False,
                    validate_on_submit: bool = True, collection_id: str | None = None,
                    discussion_type: str | None = None, event_end: str | None = None,
                    event_start: str | None = None, event_tz: str | None = None,
                    g_recaptcha_response: str | None = None):
        data = {"sr": subreddit or self.me["subreddit"]["display_name"], "text": selftext,
                "options": options, "duration": duration, "resubmit": resubmit,
                "sendreplies": send_replies, "title": title, "nsfw": nsfw, "spoiler": spoiler,
                "validate_on_submit": validate_on_submit}

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

        r = self.__request("POST", "api/submit_poll_post", json=data)
        r.raise_for_status()

        data: RedditSubmission = r.json()
        return data

    def submit_selftext(self, title: str, text: str, nsfw: bool = False, resubmit: bool = True,
                        send_replies: bool = False, spoiler: bool = False,
                        subreddit: str | None = None, collection_id: str | None = None,
                        flair_id: str | None = None, flair_text: str | None = None,
                        discussion_type: str | None = None, event_end: str | None = None,
                        event_start: str | None = None, event_tz: str | None = None,
                        g_recaptcha_response: str | None = None,
                        convert_to_richtext: bool = False):
        rt_json = None

        if convert_to_richtext is True:
            r = self.__convert_rte_body(text)
            rt_data: RedditConvertRTE = r.json()
            rt_json = dumps(rt_data["output"])
            print(rt_data)
            text = None

        r = self.__submit("self", title, text=text, nsfw=nsfw, resubmit=resubmit,
                          send_replies=send_replies, spoiler=spoiler, subreddit=subreddit,
                          collection_id=collection_id, flair_id=flair_id, flair_text=flair_text,
                          discussion_type=discussion_type, event_end=event_end,
                          event_start=event_start, event_tz=event_tz,
                          g_recaptcha_response=g_recaptcha_response, richtext_json=rt_json)
        r.raise_for_status()

        data: RedditSubmission = r.json()
        return data

    def submit_video(self, title: str, video_io: IO[bytes], video_filename: str,
                     videogif: bool = False, thumbnail_image_path: Path | None = None,
                     nsfw: bool = False, resubmit: bool = True, send_replies: bool = False,
                     spoiler: bool = False, validate_on_submit: bool = True,
                     subreddit: str | None = None, collection_id: str | None = None,
                     flair_id: str | None = None, flair_text: str | None = None,
                     discussion_type: str | None = None, event_end: str | None = None,
                     event_start: str | None = None, event_tz: str | None = None,
                     g_recaptcha_response: str | None = None):
        if thumbnail_image_path is None:
            video_poster_url = self.__upload_media(default_video_poster, "poster.png")[0]

        else:
            assert guess_type(thumbnail_image_path)[0].startswith("image")
            video_poster_url = self.__upload_media(thumbnail_image_path.open(mode="rb"),
                                                   thumbnail_image_path.name)[0]

        return self.__submit_media("videogif" if videogif else "video", title, video_io,
                                   video_filename, nsfw=nsfw, resubmit=resubmit,
                                   send_replies=send_replies, spoiler=spoiler,
                                   validate_on_submit=validate_on_submit, subreddit=subreddit,
                                   collection_id=collection_id, flair_id=flair_id,
                                   flair_text=flair_text, discussion_type=discussion_type,
                                   event_end=event_end, event_start=event_start, event_tz=event_tz,
                                   video_poster_url=video_poster_url,
                                   g_recaptcha_response=g_recaptcha_response)

    @property
    def token(self):
        return self.__token

    @property
    def token_issued_at(self):
        return self.__token_issued_at

    def upload_inline_media(self, media_stream: IO[bytes], media_filename: str):
        return self.__upload_media(media_stream, media_filename)[1]
