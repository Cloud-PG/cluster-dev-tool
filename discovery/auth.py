#! *-* coding: utf-8 *-*
import json
from abc import ABC, abstractmethod
from getpass import getpass
from time import time

import jwt

import requests
from termcolor import colored

from .utils import show

__all__ = ['IAM']


class Auth(ABC):

    @abstractmethod
    def token(self):
        pass


class IAM(Auth):

    def __init__(self, conf_file=None):
        self.endpoint = None
        self.client_id = None
        self.client_secret = None
        self.user = None
        self.grant_type = None
        self.scope = None
        self.session = {}
        self.conf_file = conf_file

        if conf_file:
            self.load_config_file()

    def update_config_file(self):
        with open(self.conf_file, "w") as file_:
            json.dump({
                'cfg': {
                    'endpoint': self.endpoint,
                    'client_id': self.client_id,
                    'client_secret': self.client_secret,
                    'user': self.user,
                    'grant_type': self.grant_type,
                    'scope': self.scope
                },
                'session': self.session
            }, file_, indent=2)
        return self

    def load_config_file(self, config_file=None):
        if config_file:
            cur_file = config_file
        else:
            cur_file = self.conf_file

        show(colored("[IAM]", "magenta"), colored(
            "[Load Config]", "yellow"), end='\r')
        with open(cur_file) as file_:
            config = json.load(file_)

        for key, value in config['cfg'].items():
            if hasattr(self, key):
                show(
                    colored("[IAM]", "magenta"),
                    colored("[Load Config]", "yellow"),
                    colored("[Set '{}'\t-> '{}']".format(key, value), "yellow"),
                    end="\r"
                )
                setattr(self, key, value)
            else:
                raise Exception(
                    "Config attribute '{}' is not valid!".format(key))

        show(colored("[IAM]", "magenta"), colored(
            "[Load Config](✓)", "green"), clean=True)

        if config.get('session'):
            self.session = config['session']
            show(colored("[IAM]", "magenta"),
                 colored("[Load session](✓)", "green"))

    def __get_token(self):
        show(colored("[IAM]", "magenta"),
             colored("[Insert Password]:", "cyan"))
        passwd = getpass("")
        show(colored("[IAM]", "magenta"),
             colored("[Request token]:", "yellow"), end='\r')
        res = requests.post(self.endpoint, data={
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'grant_type': self.grant_type,
            'username': self.user,
            'password': passwd,
            'scope': self.scope
        })
        show(colored("[IAM]", "magenta"),
             colored("[Request token](✓)", "green"))
        self.session = res.json()
        self.update_config_file()
        show(colored("[IAM]", "magenta"),
             colored("[Update file](✓)", "green"))
        return self

    def token(self):
        show(colored("[IAM]", "magenta"),
             colored("[GET token]", "yellow"), end="\r")
        if self.session.get('access_token'):
            decoded_obj = jwt.decode(self.session.get(
                'access_token'),
                algorithms=['RS256'],
                verify=False
            )
            if time() > decoded_obj['exp']:
                self.__get_token()
        else:
            self.__get_token()
        show(colored("[IAM]", "magenta"),
             colored("[Get token](✓)", "green"),
             clean=True
             )
        return self.session.get('access_token')
