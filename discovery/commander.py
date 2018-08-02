import configparser
import json
from abc import ABCMeta, abstractmethod
from getpass import getpass

import requests
from termcolor import colored

from .auth import IAM
from .utils import print_json_data, print_list, print_right_shift, show


class Commander(metaclass=ABCMeta):

    @abstractmethod
    def create(self):
        """Create a new infrastructure."""
        pass

    @abstractmethod
    def destroy(self):
        """Undeploy all the virtual machines in the infrastructure."""
        pass

    @abstractmethod
    def radl(self):
        """A string with the original specified RADL of the infrastructure."""
        pass

    @abstractmethod
    def state(self):
        """A JSON object with two elements:
            - state: a string with the aggregated state of the infrastructure.
            - vm_states: a dict indexed with the VM ID and the value the VM state.
        """
        pass

    @abstractmethod
    def contmsg(self):
        """A string with the contextualization (log) message."""
        pass

    @abstractmethod
    def outputs(self):
        """In case of TOSCA documents it will return a JSON object with the outputs of the TOSCA document."""
        pass

    @abstractmethod
    def data(self):
        """A string with the JSOMN serialized data of the infrastructure."""
        pass


class CommanderIM(Commander):

    """Commander interface for Infrastructure Manager REST API.

    Ref: http://imdocs.readthedocs.io/en/devel/REST.html
    """

    def __init__(self, config, target_name, infrastructure_name, infrastructure_id):
        self.__server_url = config['server_url']
        self.__in_id = infrastructure_id
        self.__in_name = infrastructure_name
        self.__target_name = target_name
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
        tmp = " ; ".join(["{} = {}".format(header, value)
                          for header, value in headers.items()])
        assert len(headers) == len(tmp.split(";")
                                   ), "You have some ';' in your header values..."
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

    def radl(self):
        self.__property_name('radl')

    def state(self):
        self.__property_name('state')

    def contmsg(self):
        self.__property_name('contmsg')

    def outputs(self):
        self.__property_name('outputs')

    def data(self):
        self.__property_name('data')

    def __property_name(self, property_, force=False):
        """Get the infrastructure state.

        API REST:
            GET: http://imserver.com/infrastructures/<infId>/["radl"|"state"|"contmsg"|"outputs"|"data"]
        """
        token = self.__auth.token(force=force)
        self.__header_compose(token)

        res = requests.get(
            self.__url_compose(self.__in_id, property_),
            headers=self.__headers
        )

        try:
            content = res.json()
        except json.decoder.JSONDecodeError:
            content = res.text

        result = "Response Header:\n{}\nData:\n{}".format(
            print_json_data(dict(res.headers)),
            print_json_data(res.json()) if isinstance(
                content, dict) else content
        )
        result = print_right_shift(result)
        show(
            colored("[Discovery]", "magenta"),
            colored("[{}]".format(self.__in_name), "white"),
            colored("[{}]".format(self.__target_name), "red"),
            colored("[{}]".format(property_), "green"),
            colored("[\n{}\n]".format(result), "blue")
        )

        if res.status_code == 400:
            if res.text.find("OIDC auth Token expired") != -1:
                return self.state(force=True)
