from datetime import datetime

from httpx import Response

from ._type import OAuth2Token


class OAuth2TokenException(Exception):
    pass


class OAuth2ExpiredTokenException(Exception):
    def __init__(self, token: OAuth2Token, expiry: datetime):
        super().__init__(f"OAuth2 token {token['access_token']} expired at {expiry}!")


class OAuth2RevokedTokenException(OAuth2TokenException):
    def __init__(self, token: OAuth2Token):
        self.__token = token
        self.__msg = f"Token {token['access_token']} has been revoked!"
        super().__init__(self.__msg)

    @property
    def message(self):
        return self.__msg

    @property
    def token(self):
        return self.__token


class RESTException(Exception):
    def __init__(self, res: Response):
        self.__res = res
        super().__init__(f"REST exception occurred with status code {res.status_code}!")

    @property
    def response(self):
        return self.__res
