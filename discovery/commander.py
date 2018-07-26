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


class CommanderIAM(Commander):

    def create(self):
        pass
    
    def destroy(self):
        pass
