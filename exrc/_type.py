# pyeXRC - Python Reddit client
# Copyright © 2023 - exhumer

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, version 3 of the License.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

from __future__ import annotations
from enum import StrEnum
from typing import Any, Literal, NotRequired, TypedDict


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


class GalleryImage(TypedDict):
    caption: str
    outbound_url: str
    media_id: str


class Thing(TypedDict):
    kind: str
    data: Any


class LinkData(TypedDict):
    all_awardings: list[Any]
    allow_live_comments: bool
    approved: NotRequired[bool]
    approved_at_utc: int | None
    approved_by: str | None
    archived: bool
    author: str
    author_flair_background_color: str | None
    author_flair_css_class: str | None
    author_flair_richtext: list[Any]
    author_flair_template_id: str | None
    author_flair_text: str | None
    author_flair_text_color: str | None
    author_flair_type: str
    author_fullname: str
    author_is_blocked: bool
    author_patreon_flair: bool
    author_premium: bool
    awarders: list[Any]
    banned_at_utc: int | None
    banned_by: str | None
    can_gild: bool
    can_mod_post: bool
    category: str | None
    clicked: bool
    content_categories: None
    contest_mode: bool
    created: int
    created_utc: int
    discussion_type: str | None
    distinguished: str | None
    domain: str
    downs: int
    edited: bool
    gilded: int
    gildings: dict[str, Any]
    hidden: bool
    hide_score: bool
    id: str
    ignore_reports: NotRequired[bool]
    is_created_from_ads_ui: bool
    is_crosspostable: bool
    is_meta: bool
    is_original_content: bool
    is_reddit_media_domain: bool
    is_robot_indexable: bool
    is_self: bool
    is_video: bool
    likes: bool | None
    link_flair_background_color: str
    link_flair_css_class: str | None
    link_flair_richtext: list[dict[str, str]]
    link_flair_template_id: NotRequired[str]
    link_flair_text: str | None
    link_flair_text_color: str
    link_flair_type: str
    locked: bool
    media: dict[str, Any] | None
    media_embed: dict[str, Any]
    media_only: bool
    mod_note: str | None
    mod_reason_by: str | None
    mod_reason_title: str | None
    mod_reports: list[Any]
    name: str
    no_follow: bool
    num_comments: int
    num_crossposts: int
    num_duplicates: int
    num_reports: int | None
    over_18: bool
    parent_whitelist_status: None
    permalink: str
    pinned: bool
    post_hint: NotRequired[str]
    preview: NotRequired[dict[str, Any]]
    pwls: None
    quarantine: bool
    removal_reason: str | None
    removed: NotRequired[bool]
    removed_by: str | None
    removed_by_category: str | None
    report_reasons: list[Any] | None
    rte_mode: NotRequired[str]
    saved: bool
    score: int
    secure_media: dict[str, Any] | None
    secure_media_embed: dict[str, Any]
    selftext: str
    selftext_html: str | None
    send_replies: bool
    spam: NotRequired[bool]
    spoiler: bool
    stickied: bool
    subreddit: str
    subreddit_id: str
    subreddit_name_prefixed: str
    subreddit_subscribers: int
    subreddit_type: str
    suggested_sort: str | None
    thumbnail: str
    thumbnail_height: int | None
    thumbnail_width: int | None
    title: str
    top_awarded_type: None
    total_awards_received: int
    treatment_tags: list[Any]
    ups: int
    upvote_ratio: int | float
    url: str
    url_overridden_by_dest: NotRequired[str]
    user_reports: list[Any]
    view_count: int | None
    visited: bool
    whitelist_status: None
    wls: None


class LinkThing(Thing):
    data: LinkData


class Listing(Thing):
    kind: Literal["Listing"]
    data: ListingData


class ListingData(TypedDict):
    after: str | None
    dist: int | None
    modhash: str
    geo_filter: str
    children: list[Thing]
    before: str | None


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


class MediaAsset(TypedDict):
    args: MediaAssetArgs
    asset: MediaAssetAsset


class MediaAssetArgs(TypedDict):
    action: str
    fields: list[dict[Literal["name", "value"], str]]


class MediaAssetAsset(TypedDict):
    asset_id: str
    processing_state: str
    payload: MediaAssetAssetPayload
    websocket_url: str


class MediaAssetAssetPayload(TypedDict):
    filepath: str


class MediaAssetUploadData(TypedDict):
    Location: str
    Bucket: str
    Key: str
    ETag: str


class MediaKind(StrEnum):
    IMAGE = "image"
    VIDEO = "video"
    VIDEO_GIF = "videogif"


class MediaSubmission(TypedDict):
    json: MediaSubmissionJSON


class MediaSubmissionJSON(TypedDict):
    errors: list
    data: MediaSubmissionJSONData


class MediaSubmissionJSONData(TypedDict):
    redirect: str


class MediaSubmissionUpdate(TypedDict):
    type: str
    payload: MediaSubmissionUpdatePayload


class MediaSubmissionUpdatePayload(TypedDict):
    redirect: str


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
    Remaining: int
    Reset: str
    Used: int


class Submission(TypedDict):
    json: SubmissionJSON


class SubmissionData(TypedDict):
    url: str
    drafts_count: NotRequired[int]
    id: str
    name: NotRequired[str]


class SubmissionJSON(TypedDict):
    data: SubmissionData


class SubmitKind(StrEnum):
    IMAGE = "image"
    LINK = "link"
    SELF = "self"
    VIDEO = "video"
    VIDEO_GIF = "videogif"


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
