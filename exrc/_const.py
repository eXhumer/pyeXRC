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

from pkg_resources import require, resource_stream


__version__ = require(__package__)[0].version
BASE_URL = "https://www.reddit.com"
OAUTH_URL = "https://oauth.reddit.com"
ACCESS_TOKEN_URL = "api/v1/access_token"
REVOKE_TOKEN_URL = "api/v1/revoke_token"
SCOPES_URL = "api/v1/scopes"
USER_AGENT = f"{__package__}/{__version__}"
VIDEO_POSTER = resource_stream(__name__, "default_video_poster.png")
