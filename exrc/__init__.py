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

"""Reddit OAuth2 Client Library Module"""
from pkg_resources import require

from ._client import RedditOAuth2Client  # noqa: F401
from ._model import RedditOAuth2Token  # noqa: F401

__version__ = require(__package__)[0].version
