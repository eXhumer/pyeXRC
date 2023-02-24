from pkg_resources import require


__version__ = require(__package__)[0].version
BASE_URL = "https://www.reddit.com"
OAUTH_URL = "https://oauth.reddit.com"
ACCESS_TOKEN_URL = "api/v1/access_token"
REVOKE_TOKEN_URL = "api/v1/revoke_token"
USER_AGENT = f"{__package__}/{__version__}"
