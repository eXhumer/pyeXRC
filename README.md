# eXRC
Reddit OAuth2 client to access Reddit resources via [OAuth2](https://github.com/reddit-archive/reddit/wiki/OAuth2), powered by [requests](https://pypi.org/project/requests/), [requests-toolbelt](https://pypi.org/project/requests-toolbelt/) & [websocket-client](https://pypi.org/project/websocket-client/). 

## Client Features
* Supports all forms of OAuth2 flows/grants supported by Reddit.
* Supports request rate limit handling support (Throws `exrc.exception.RateLimitException` on rate limited, which provides access to method `sleep_until_reset` to sleep client until rate limit is reset).
* Provides HTTP methods as client methods to access Reddit resources.
* Provides methods to refresh/revoke OAuth2 credentials.
* Provides methods to save/load OAuth2 credential from token file.

## Package Installation Guide
### Requires
* Python 3.9+
* pip package manager

### Install from source
```console
pip install .
```

## Licensing
This project is licensed under OSI Approved [GNU GPLv3 **ONLY**](https://github.com/eXhumer/pyeXRC/blob/python3/LICENSE.md).
