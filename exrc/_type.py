from __future__ import annotations
from datetime import datetime
from enum import StrEnum
from typing import Literal, NotRequired, TypedDict


class CommentsSort(StrEnum):
    CONFIDENCE = "confidence"
    TOP = "top"
    NEW = "new"
    CONTROVERSIAL = "controversial"
    OLD = "old"
    RANDOM = "random"
    QA = "qa"
    LIVE = "live"
    BLANK = "blank"


class ListingSort(StrEnum):
    BEST = "best"
    HOT = "hot"
    NEW = "new"
    RISING = "rising"
    CONTROVERSIAL = "controversial"
    TOP = "top"


class Me(TypedDict):
    accept_followers: bool
    awardee_karma: int
    awarder_karma: int
    can_create_subreddit: bool
    can_edit_name: bool
    coins: int
    comment_karma: int
    created_utc: int
    created: int
    force_password_reset: bool
    gold_creddits: int
    gold_expiration: int | None
    has_android_subscription: bool
    has_external_account: bool
    has_gold_subscription: bool
    has_ios_subscription: bool
    has_paypal_subscription: bool
    has_stripe_subscription: bool
    has_subscribed_to_premium: bool
    has_subscribed: bool
    has_verified_email: bool
    has_visited_new_profile: bool
    hide_from_robots: bool
    icon_img: str
    id: str
    in_beta: bool
    in_redesign_beta: bool
    inbox_count: int
    is_employee: bool
    is_gold: bool
    is_mod: bool
    is_sponsor: bool
    is_suspended: bool
    link_karma: int
    linked_identities: list[str]
    name: str
    num_friends: int
    oauth_client_id: str
    over_18: bool
    password_set: bool
    pref_autoplay: bool
    pref_clickgadget: int
    pref_geopopular: str
    pref_nightmode: bool
    pref_no_profanity: bool
    pref_show_presence: bool
    pref_show_snoovatar: bool
    pref_show_trending: bool
    pref_show_twitter: bool
    pref_top_karma_subreddits: bool
    pref_video_autoplay: bool
    seen_give_award_tooltip: bool
    seen_layout_switch: bool
    seen_premium_adblock_modal: bool
    seen_redesign_modal: bool
    seen_subreddit_chat_ftux: bool
    snoovatar_img: str
    snoovatar_size: list[int]
    subreddit: Subreddit
    suspension_expiration_utc: int | None
    total_karma: int
    verified: bool


class OAuth2Scope(TypedDict):
    description: str
    id: str
    name: str


OAuth2Scopes = dict[str, OAuth2Scope]


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


class Subreddit(TypedDict):
    accept_followers: bool
    banner_img: str
    banner_size: list[int] | None
    coins: NotRequired[int]
    community_icon: str | None
    default_set: NotRequired[bool]
    description: str
    disable_contributor_requests: bool
    display_name_prefixed: str
    display_name: str
    free_form_reports: bool
    header_img: str | None
    header_size: list[int] | None
    icon_color: str | None
    icon_img: str
    icon_size: list[int]
    is_default_banner: NotRequired[bool]
    is_default_icon: NotRequired[bool]
    key_color: str
    link_flair_enabled: bool
    link_flair_position: str
    name: str
    over_18: NotRequired[bool]
    previous_names: NotRequired[list[str]]
    primary_color: str
    public_description: str
    quarantine: bool
    restrict_commenting: bool
    restrict_posting: bool
    show_media: bool
    submit_link_label: str
    subreddit_type: str
    title: str
    url: str
    user_is_banned: bool
    user_is_contributor: bool
    user_is_moderator: bool
    user_is_muted: bool | None
    user_is_subscriber: bool