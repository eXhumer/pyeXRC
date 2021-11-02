# eXRC - Reddit OAuth2 Client
# Copyright (C) 2021 - eXhumer

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
from pkg_resources import require, resource_stream

__version__ = require(__package__)[0].version
default_user_agent = f"{__package__}/{__version__}"
default_video_poster = resource_stream(__name__, "default_video_poster.png")
