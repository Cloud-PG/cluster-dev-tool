import configparser
from abc import ABC, abstractmethod
from getpass import getpass

import requests
from termcolor import colored

from .auth import IAM
from .utils import print_json_data, print_list, print_right_shift, show


class Commander(object):

    @abstractmethod
    def create(self):
        pass

    @abstractmethod
    def destroy(self):
        pass


class CommanderIM(Commander):

    """Commander interface for Infrastructure Manager REST API.

    Ref: http://imdocs.readthedocs.io/en/devel/REST.html
    """

    def __init__(self, config, infrastructure_name, infrastructure_id):
        self.__server_url = config['server_url']
        self.__in_id = infrastructure_id
        self.__in_name = infrastructure_name
        self.__headers = {}
        self.__auth = None
        self.__config = config

        # prepare auth
        if config['auth']['type'] == "IAM":
            self.__auth = IAM(config['auth'].get('config_file', None))
        else:
            raise Exception("Auth '{}' is not supported...".format(
                config['auth']['type']))

    def __url_compose(self, *args):
        return "{}/{}".format(self.__server_url, "/".join(args))

    def __unroll_header(self, **headers):
        tmp = " ; ".join(["{} = {}".format(header, value) for header, value in headers.items()])
        assert len(headers) == len(tmp.split(";")), "You have some ';' in your header values..."
        return tmp

    def __header_compose(self, token):
        """Generate the header for IM.

        Note: Every HTTP request must be companied by the header AUTHORIZATION with 
              the content of the Authorization File, but putting all the elements in 
              one line using “\n” as separator.
        """
        self.__headers = {}

        for header, value in [(_h_, _) for _h_, _ in self.__config['headers'].items() if _h_ not in ['authorization', 'auth']]:
            self.__headers[header] = value

        self.__headers['authorization'] = "{}\\n{}".format(
            self.__unroll_header(
                password=token,
                **self.__config['headers']['authorization']
            ),
            self.__unroll_header(
                token=token,
                **self.__config['headers']['auth']
            )
        )

    def create(self):
        pass

    def destroy(self):
        pass

    def state(self, force=False):
        """Get the infrastructure state.

        API REST:
            GET: http://imserver.com/infrastructures/<infId>/state
        """
        token = self.__auth.token(force=force)
        self.__header_compose(token)

        res = requests.get(
            self.__url_compose(self.__in_id, 'state'),
            headers=self.__headers
        )

        result = "Response Header:\n{}\nData:\n{}".format(
            print_json_data(dict(res.headers)),
            print_json_data(res.json())
        )
        result = print_right_shift(result)
        show(
            colored("[Discovery]", "magenta"),
            colored("[{}]".format(self.__in_name), "white"),
            colored("[state]", "green"),
            colored("[\n{}\n]".format(result), "blue")
        )

        if res.status_code == 400:
            if res.text.find("OIDC auth Token expired") != -1:
                return self.state(force=True)
