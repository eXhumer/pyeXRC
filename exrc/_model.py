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

from __future__ import annotations
from typing import Any, Dict, List, Literal, NotRequired, TypedDict


class RedditClientCredential(TypedDict):
    client_id: str
    client_secret: NotRequired[str]


class RedditConvertRTE(TypedDict):
    output: RedditConvertRTEOutput
    output_mode: str
    assets: List[str]


class RedditConvertRTEOutput(TypedDict):
    document: List[Dict[str, Any]]


class RedditMe(TypedDict):
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
    linked_identities: List[str]
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
    snoovatar_size: List[int]
    subreddit: RedditSubreddit
    suspension_expiration_utc: int | None
    total_karma: int
    verified: bool


class RedditMediaAsset(TypedDict):
    args: RedditMediaAssetArgs
    asset: RedditMediaAssetAsset


class RedditMediaAssetArgs(TypedDict):
    action: str
    fields: List[RedditMediaAssetArgsField]


class RedditMediaAssetAsset(TypedDict):
    asset_id: str
    processing_state: str
    payload: RedditMediaAssetAssetPayload
    websocket_url: str


class RedditMediaAssetAssetPayload(TypedDict):
    fielpath: str


class RedditMediaAssetArgsField(TypedDict):
    name: str
    value: str


class RedditMediaSubmission(TypedDict):
    json: RedditMediaSubmissionData


class RedditMediaSubmissionData(TypedDict):
    user_submitted_page: str
    websocket_url: str


class RedditMediaUploadUpdate(TypedDict):
    type: str
    payload: RedditMediaUploadUpdatePayload


class RedditMediaUploadUpdatePayload(TypedDict):
    redirect: str


class RedditOAuth2Token(TypedDict):
    access_token: str
    device_id: NotRequired[str]
    expires_in: int
    refresh_token: NotRequired[str]
    scope: str
    token_type: Literal["bearer"]


class RedditScopeV1(TypedDict):
    description: str
    id: str
    name: str


class RedditSubmission(TypedDict):
    json: RedditSubmissionJSON


class RedditSubmissionData(TypedDict):
    url: str
    drafts_count: NotRequired[int]
    id: str
    name: NotRequired[str]


class RedditSubmissionJSON(TypedDict):
    data: RedditSubmissionData


class RedditSubreddit(TypedDict):
    accept_followers: bool
    banner_img: str
    banner_size: List[int] | None
    coins: NotRequired[int]
    community_icon: str | None
    default_set: NotRequired[bool]
    description: str
    disable_contributor_requests: bool
    display_name_prefixed: str
    display_name: str
    free_form_reports: bool
    header_img: str | None
    header_size: List[int] | None
    icon_color: str | None
    icon_img: str
    icon_size: List[int]
    is_default_banner: NotRequired[bool]
    is_default_icon: NotRequired[bool]
    key_color: str
    link_flair_enabled: bool
    link_flair_position: str
    name: str
    over_18: NotRequired[bool]
    previous_names: NotRequired[List[str]]
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


RedditScopesV1 = Dict[str, RedditScopeV1]
