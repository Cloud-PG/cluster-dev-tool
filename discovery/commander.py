import configparser
from abc import ABC, abstractmethod
from getpass import getpass

import requests

from .auth import IAM


class Commander(object):

    @abstractmethod
    def create(self):
        pass

    @abstractmethod
    def destroy(self):
        pass


class CommanderIM(Commander):

    def __init__(self, server_url, headers={}):
        self.__server_url = server_url
        self.__base_headers = {
            'type': 'OpenStack',
            'domain': "default",
            'id': "im",
            'type': "InfrastructureManager"
        }

        for header, value in headers.items():
            self.__base_headers[header] = value

    def create(self):
        pass
    
    def destroy(self):
        pass
    
    def state(self):
        pass
