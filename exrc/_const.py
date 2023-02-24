from pkg_resources import require, resource_stream


__version__ = require(__package__)[0].version
BASE_URL = "https://www.reddit.com"
OAUTH_URL = "https://oauth.reddit.com"
ACCESS_TOKEN_URL = "api/v1/access_token"
REVOKE_TOKEN_URL = "api/v1/revoke_token"
SCOPES_URL = "api/v1/scopes"
USER_AGENT = f"{__package__}/{__version__}"
VIDEO_POSTER = resource_stream(__name__, "default_video_poster.png")
