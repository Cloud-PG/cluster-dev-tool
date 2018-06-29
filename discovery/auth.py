import configparser
from getpass import getpass
from abc import ABC, abstractmethod
import json

import requests


__all__ = ['IAM']


class Auth(ABC):

    @abstractmethod
    def token(self):
        pass


class IAM(Auth):

    def __init__(self, conf_file, session_filename="auth_session.json"):
        self.endpoint = None
        self.client_id = None
        self.client_secret = None
        self.user = None
        self.grant_type = None
        self.scope = None
        self.session_filename = session_filename

        self.data = type('Data', (object,), {
            'access_token': None,
            'token_type': None,
            'refresh_token': None,
            'expires_in': None,
            'scope': None,
            'id_token': None
        })()

        config = configparser.ConfigParser()
        config.read(conf_file)

        for key, value in config['IAM'].items():
            if hasattr(self, key):
                setattr(self, key, value)

    def __get_token(self):
        passwd = getpass("Password: ")
        res = requests.post(self.endpoint, data={
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'grant_type': self.grant_type,
            'username': self.user,
            'password': passwd,
            'scope': self.scope
        })

        for key, value in res.json().items():
            setattr(self.data, key, value)

        with open(self.session_filename, "w") as out_file:
            tmp = dict((key, val) for key, val in vars(self).items())
            tmp['data'] = dict((key, val) for key, val in vars(self.data).items())
            json.dump(tmp, out_file, indent=2)

        return self

    def token(self):
        if not self.data.access_token:
            self.__get_token()
        return self.data.access_token


print(IAM("../iam.cfg").token())
