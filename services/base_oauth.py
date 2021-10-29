from flask import request
import urllib
import requests

from CTFd.utils import config, email, get_app_config, get_config
from CTFd.utils.helpers import error_for, get_errors, markup
from CTFd.utils.logging import log

class BaseOAuth(object):
    
    id = None
    name = None

    client_id = None
    client_secret = None

    redirect_uri = None
    scope = None

    auth_endpoint = None

    #callback_uri = None
    urlencoded_header = {"Content-type": "application/x-www-form-urlencoded"}
    default_scope = None

    oauth2_url = None

    endpoint_path = None

    @classmethod
    def auth_url(cls):
        raw_query = cls.auth_query()
        enc_query = urllib.parse.urlencode(raw_query)
        return cls.auth_endpoint + "?" + enc_query

    @classmethod
    def auth_query(cls):
        return {
            "client_id": cls.client_id,
            "redirect_uri": cls.redirect_uri,
            "scope": cls.scope,
            "response_type": "code"
        }

    @classmethod
    def get_token(cls):
        response = requests.post(
            oauth2_url,
            headers=cls.urlencoded_header,
            params=scope
        )
        return response

    

    @staticmethod
    def authorization_token_header(cls, access_token, token_type="Bearer"):
        return "{} {}".format(token_type, access_token)

    @staticmethod
    def refresh_token(cls, access_token):
        pass
