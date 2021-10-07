from flask import Blueprint, render_template, render_template_string, request, redirect, url_for, session
import urllib
import requests
import os
import json

from CTFd.config import config_ini, empty_str_cast
from CTFd import challenges
from CTFd.auth import auth
from CTFd.plugins import register_plugin_assets_directory
from CTFd.models import Teams, UserFieldEntries, UserFields, Users, db
#from CTFd.models import db, Users
from CTFd.utils import config, email, get_app_config, get_config
from CTFd.utils import validators
from CTFd.utils import user as current_user
from CTFd.utils.crypto import verify_password
from CTFd.utils.helpers import error_for, get_errors, markup
#from CTFd.utils import email
from CTFd.utils.logging import log
from CTFd.utils.security.auth import login_user, logout_user
from CTFd.utils.decorators.visibility import check_registration_visibility

from CTFd.plugins.simple_oauth2.services.base_oauth import BaseOAuth

class GoogleOAuth(BaseOAuth):
    id = "g_oauth2"
    name = "Google OAuth2.0"

    client_id = empty_str_cast(config_ini["oauth"]["G_OAUTH_CLIENT_ID"])
    
    client_secret = empty_str_cast(config_ini["oauth"]["G_OAUTH_CLIENT_SECRET"])
    
    scope = "https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/userinfo.email"
    #redirect_uri = "http://localhost"

    auth_endpoint = "https://accounts.google.com/o/oauth2/auth"

    #redirect_uri = get_app_config("G_OAUTH_REDIRECT_URI")
    endpoint_path = "/o/g/redirect"

    @classmethod
    def get_email(cls, token):
        pass

    #@classmethod
    #def auth_url(cls):
    #    raw_query = cls.auth_query()
    #    enc_query = urllib.parse.urlencode(raw_query)
    #    return cls.auth_endpoint + "?" + enc_query
        

    @classmethod
    def auth_query(cls):
        return {
            "client_id": cls.client_id,
            "redirect_uri": urllib.parse.urljoin(request.host_url, cls.endpoint_path),
            "scope": cls.scope,
            "response_type": "code"
        }
    
    @classmethod
    def request_token(cls):
        headers = {"Content-type": "application/x-www-form-urlencoded"}
        payload = dict(filter(lambda query: (query[0] in ["code", "scope"]), request.args.items()))
        payload["client_id"] = cls.client_id
        payload["client_secret"] = cls.client_secret
        # https://tedboy.github.io/flask/generated/generated/flask.Request.html
        # requestが無いところで呼ばれた時どうしよう～
        payload["redirect_uri"] = request.base_url
        #payload["redirect_uri"] = (request and request.base_url) \
        #                       or "http://localhost/o/g/redirect"
        payload["grant_type"] = "authorization_code"
        return requests.post("https://accounts.google.com/o/oauth2/token", headers=headers, params=payload)

    @classmethod
    def request_email(cls, token, token_type="Bearer"):

        bearer_auth = {"Content-type": "application/x-www-form-urlencoded", "authorization": "Bearer {}".format(token)}
    
        return requests.get("https://www.googleapis.com/oauth2/v1/userinfo", headers=bearer_auth)

 