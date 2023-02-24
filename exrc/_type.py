from __future__ import annotations
from datetime import datetime
from typing import Literal, NotRequired, TypedDict


class OAuth2Token(TypedDict):
    access_token: str
    device_id: NotRequired[str]
    expires_in: int
    refresh_token: NotRequired[str]
    scope: str
    token_type: Literal["bearer"]


class RateLimit(TypedDict):
    Remaining: float
    Reset: datetime
    Used: int
