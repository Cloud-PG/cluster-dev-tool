import configparser
import json
from abc import ABCMeta, abstractmethod
from getpass import getpass

import requests
from termcolor import colored

from .auth import IAM
from .utils import (filter_output, print_json_data, print_list,
                    print_right_shift, show)


class Commander(metaclass=ABCMeta):

    @abstractmethod
    def create(self, name, data=None):
        """Create a new infrastructure."""
        pass

    @abstractmethod
    def destroy(self):
        """Undeploy all the virtual machines in the infrastructure."""
        pass

    @abstractmethod
    def radl(self, output_filter=None):
        """A string with the original specified RADL of the infrastructure."""
        pass

    @abstractmethod
    def state(self, output_filter=None):
        """A JSON object with two elements:
            - state: a string with the aggregated state of the infrastructure.
            - vm_states: a dict indexed with the VM ID and the value the VM state.
        """
        pass

    @abstractmethod
    def contmsg(self, output_filter=None):
        """A string with the contextualization (log) message."""
        pass

    @abstractmethod
    def outputs(self, output_filter=None):
        """In case of TOSCA documents it will return a JSON object with the outputs of the TOSCA document."""
        pass

    @abstractmethod
    def data(self, output_filter=None):
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

    def __header_compose(self, token, additional_headers={}):
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

        self.__headers.update(additional_headers)

    def create(self, name, data=None):
        token = self.__auth.token()
        self.__header_compose(token, additional_headers={
            'Content-type': "text/yaml"
        })

        with open(data) as yaml_template:
            res = requests.post(
                self.__url_compose(),
                headers=self.__headers,
                data=yaml_template
            )

        result = self.__prepare_result(res)

    def destroy(self):
        pass

    def radl(self, output_filter=None):
        self.__property_name('radl', output_filter=output_filter)

    def state(self, output_filter=None):
        self.__property_name('state', output_filter=output_filter)

    def contmsg(self, output_filter=None):
        self.__property_name('contmsg', output_filter=output_filter)

    def outputs(self, output_filter=None):
        self.__property_name('outputs', output_filter=output_filter)

    def data(self, output_filter=None):
        self.__property_name('data', output_filter=output_filter)

    def __prepare_result(self, res, output_filter=None):
        try:
            content = res.json()
        except json.decoder.JSONDecodeError:
            content = res.text

        result = "Response Header:\n{}\nData:\n{}".format(
            print_json_data(dict(res.headers)),
            print_json_data(res.json()) if isinstance(
                content, dict) else content
        )

        if output_filter:
            result = filter_output(result, output_filter)

        result = print_right_shift(result)
        return result

    def __property_name(self, property_, force=False, output_filter=None):
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

        result = self.__prepare_result(res, output_filter=output_filter)

        show(
            colored("[Discovery]", "magenta"),
            colored("[{}]".format(self.__in_name), "white"),
            colored("[{}]".format(self.__target_name), "red"),
            colored("[{}]".format(property_), "green"),
            colored("[\n{}\n]".format(result), "blue")
        )

        if res.status_code == 400:
            if res.text.find("OIDC auth Token expired") != -1:
                return self.__property_name(property_, force=True)
