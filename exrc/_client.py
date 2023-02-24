from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from json import dumps
from random import choice
from string import ascii_letters, digits
from typing import Literal
from urllib.parse import urlparse
from webbrowser import open as webbrowser_open

from httpx import BasicAuth, Client

from ._const import ACCESS_TOKEN_URL, BASE_URL, OAUTH_URL, REVOKE_TOKEN_URL, SCOPES_URL, USER_AGENT
from ._exception import OAuth2ExpiredTokenException, OAuth2RevokedTokenException, RESTException
from ._type import CommentsSort, ListingSort, Me, OAuth2Scopes, OAuth2Token, RateLimit, \
    Submission, SubmitKind
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

    def _submit(self, kind: SubmitKind, title: str, subreddit: str | None = None,
                text: str | None = None, url: str | None = None,
                video_poster_url: str | None = None, nsfw: bool = False, resubmit: bool = True,
                send_replies: bool = False, spoiler: bool = False,
                collection_id: str | None = None, flair_id: str | None = None,
                flair_text: str | None = None, discussion_type: str | None = None,
                event_end: str | None = None, event_start: str | None = None,
                event_tz: str | None = None, g_recaptcha_response: str | None = None,
                richtext_json: dict | None = None):
        assert not (text is not None and richtext_json is not None)

        data = {"api_type": "json", "nsfw": nsfw, "resubmit": resubmit,
                "sendreplies": send_replies, "spoiler": spoiler, "title": title, "kind": kind,
                "submit_type": "subreddit" if subreddit else "profile"}

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
            ("sr", subreddit),
        ):
            if value is not None:
                if key == "richtext_json":
                    value = dumps(value, separators=(",", ":"))

                data |= {key: value}

        return self._request("POST", "api/submit", data=data)

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

    def comment(self, thing_id: str, text: str | None = None, richtext_json: dict | None = None):
        assert text or richtext_json
        data = {"api_type": "json", "return_rtjson": richtext_json is not None, "text": text or "",
                "thing_id": thing_id}

        if richtext_json:
            data |= {"richtext_json": dumps(richtext_json, separators=(",", ":"))}

        return self._request("POST", "api/comment", data=data)

    def comments(self, post_id: str, sort: CommentsSort = CommentsSort.CONFIDENCE,
                 subreddit: str | None = None, comment: str | None = None,
                 context: int | None = None, depth: int | None = None, limit: int | None = None,
                 showedits: bool | None = None, showmedia: bool | None = None,
                 showmore: bool | None = None, showtitle: bool | None = None,
                 threaded: bool | None = None, truncate: int | None = None):
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
                params |= {key: value}

        if subreddit is not None:
            return self._request("GET", f"comments/{post_id}", params=params)

        return self._request("GET", f"r/{subreddit}/comments/{post_id}", params=params)

    def convert_rte_body(self, md_text: str):
        return self._request("POST", "api/convert_rte_body_format",
                             data={"output_mode": "rtjson", "markdown_text": md_text})

    def delete_thing(self, thing_id: str):
        return self._request("POST", "api/del", data={"id": thing_id})

    def editusertext(self, thing_id: str, text: str | None = None,
                     richtext_json: dict | None = None):
        assert text or richtext_json
        data = {"api_type": "json", "return_rtjson": richtext_json is not None, "text": text or "",
                "thing_id": thing_id}

        if richtext_json:
            data |= {"richtext_json": dumps(richtext_json, separators=(",", ":"))}

        return self._request("POST", "api/editusertext", data=data)

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

    def info(self, ids: list[str] | None = None, sr_names: list[str] | None = None,
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
            return self._request("GET", f"r/{subreddit}/api/info", params=params)

        return self._request("GET", "api/info", params=params)

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

    @property
    def me(self):
        me_res = self._request("GET", "api/v1/me")
        me_data: Me = me_res.json()
        return me_data

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

    def posts(self, subreddit: str | None = None, sort: ListingSort = ListingSort.BEST,
              before: str | None = None, limit: int | None = None):
        params = {}

        if before:
            params |= {"before": before}

        if limit:
            params |= {"limit": limit}

        return self._request("GET", f"r/{subreddit}/{sort}" if subreddit else sort, params=params)

    def revoke(self):
        if "refresh_token" in self.__token:
            data = {"token": self.__token["refresh_token"], "token_type_hint": "refresh_token"}

        else:
            data = {"token": self.__token["access_token"], "token_type_hint": "access_token"}

        res = OAuth2Client.__CLIENT.post(f"{BASE_URL}/{REVOKE_TOKEN_URL}", data=data,
                                         auth=BasicAuth(username=self.__client_id,
                                                        password=self.__client_secret or ""))

        if res.status_code >= 400:
            raise RESTException(res)

        raise OAuth2RevokedTokenException(self.__token)

    def sendreplies(self, thing_id: str, state: bool):
        return self._request("POST", "api/sendreplies", data={"id": thing_id, "state": state})

    @staticmethod
    def scopes():
        res = OAuth2Client.__CLIENT.get(f"{BASE_URL}/{SCOPES_URL}")

        if res.status_code >= 400:
            raise RESTException(res)

        scopes: OAuth2Scopes = res.json()
        return scopes

    def submit_link(self, title: str, url: str, nsfw: bool = False, resubmit: bool = True,
                    send_replies: bool = False, spoiler: bool = False,
                    subreddit: str | None = None, collection_id: str | None = None,
                    flair_id: str | None = None, flair_text: str | None = None,
                    discussion_type: str | None = None, event_end: str | None = None,
                    event_start: str | None = None, event_tz: str | None = None,
                    g_recaptcha_response: str | None = None):
        res = self._submit(SubmitKind.LINK, title, subreddit=subreddit, url=url, nsfw=nsfw,
                           resubmit=resubmit, send_replies=send_replies, spoiler=spoiler,
                           collection_id=collection_id, flair_id=flair_id, flair_text=flair_text,
                           discussion_type=discussion_type, event_end=event_end,
                           event_start=event_start, event_tz=event_tz,
                           g_recaptcha_response=g_recaptcha_response)

        data: Submission = res.json()
        return data

    def submit_poll(self, title: str, selftext: str, options: list[str], duration: int,
                    subreddit: str | None = None, flair_id: str | None = None,
                    flair_text: str | None = None, resubmit: bool = True,
                    send_replies: bool = False, nsfw: bool = False, spoiler: bool = False,
                    collection_id: str | None = None, discussion_type: str | None = None,
                    event_end: str | None = None, event_start: str | None = None,
                    event_tz: str | None = None, g_recaptcha_response: str | None = None):
        data = {"text": selftext, "options": options, "duration": duration, "resubmit": resubmit,
                "sendreplies": send_replies, "title": title, "nsfw": nsfw, "spoiler": spoiler,
                "submit_type": "subreddit" if subreddit else "profile"}

        for key, value in (
            ("flair_id", flair_id),
            ("flair_text", flair_text),
            ("collection_id", collection_id),
            ("discussion_type", discussion_type),
            ("event_end", event_end),
            ("event_start", event_start),
            ("event_tz", event_tz),
            ("g-recaptcha-response", g_recaptcha_response),
            ("sr", subreddit),
        ):
            if value is not None:
                data |= {key: value}

        res = self._request("POST", "api/submit_poll_post", json=data)

        data: Submission = res.json()
        return data

    def submit_selftext(self, title: str, text: str | None = None, subreddit: str | None = None,
                        nsfw: bool = False, resubmit: bool = True, send_replies: bool = False,
                        spoiler: bool = False, collection_id: str | None = None,
                        flair_id: str | None = None, flair_text: str | None = None,
                        discussion_type: str | None = None, event_end: str | None = None,
                        event_start: str | None = None, event_tz: str | None = None,
                        g_recaptcha_response: str | None = None,
                        richtext_json: dict | None = None):
        res = self._submit(SubmitKind.SELF, title, subreddit=subreddit, text=text, nsfw=nsfw,
                           resubmit=resubmit, send_replies=send_replies, spoiler=spoiler,
                           collection_id=collection_id, flair_id=flair_id, flair_text=flair_text,
                           discussion_type=discussion_type, event_end=event_end,
                           event_start=event_start, event_tz=event_tz,
                           g_recaptcha_response=g_recaptcha_response, richtext_json=richtext_json)

        data: Submission = res.json()
        return data
