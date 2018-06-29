import configparser
from getpass import getpass
from abc import ABC, abstractmethod

import requests


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