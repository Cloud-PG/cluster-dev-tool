import configparser
import json
import socket
from abc import ABCMeta, abstractmethod
from getpass import getpass

import paramiko
import requests
from radl.radl_parse import parse_radl
from termcolor import colored

from .auth import IAM
from .utils import (extract_in_id, filter_output, print_json_data, print_list,
                    print_right_shift, show)


class SSHHandler(object):

    def __init__(self, ip, user, username, password=None, public_key=None, private_key=None):
        self.__ip = ip
        self.__user = user
        self.__password = password
        self.__public_key = public_key
        self.__private_key = private_key
        self.__ssh = paramiko.SSHClient()
        self.__ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    def __connect(self):
        show(
            colored("[Discovery]", "magenta"),
            colored("[vm]", "white"),
            colored("[{}]".format(self.__ip), "cyan")
        )
        if not self.__private_key and not self.__password:
            password = getpass(
                "[Insert User {} password]...".format(self.__user))
            self.__ssh.connect(
                self.__ip, username=self.__user, password=password)
        elif self.__password:
            self.__ssh.connect(self.__ip, username=self.__user,
                               password=self.__password)
        else:
            self.__ssh.connect(self.__ip, username=self.__user,
                               pkey=self.__private_key)

    def __enter__(self):
        self.__connect()
        return self

    def __exit__(self, type_, value, traceback):
        self.__ssh.close()

    def exec(self, command):
        stdin, stdout, stderr = self.__ssh.exec_command(command)
        return stdin, stdout, stderr


class Commander(metaclass=ABCMeta):

    @abstractmethod
    def create(self, name, data_path=None, show_output=True):
        """Create a new infrastructure."""
        pass

    @abstractmethod
    def delete(self, show_output=True):
        """Undeploy all the virtual machines in the infrastructure."""
        pass

    @abstractmethod
    def reconfigure(self, show_output=True):
        """Reconfigure the infrastructure."""
        pass

    @abstractmethod
    def radl(self, show_output=True, output_filter=None):
        """A string with the original specified RADL of the infrastructure."""
        pass

    @abstractmethod
    def state(self, show_output=True, output_filter=None):
        """A JSON object with two elements:
            - state: a string with the aggregated state of the infrastructure.
            - vm_states: a dict indexed with the VM ID and the value the VM state.
        """
        pass

    @abstractmethod
    def contmsg(self, show_output=True, output_filter=None):
        """A string with the contextualization (log) message."""
        pass

    @abstractmethod
    def outputs(self, show_output=True, output_filter=None):
        """In case of TOSCA documents it will return a JSON object with the outputs of the TOSCA document."""
        pass

    @abstractmethod
    def data(self, show_output=True, output_filter=None):
        """A string with the JSOMN serialized data of the infrastructure."""
        pass

    @abstractmethod
    def info(self, show_output=True, output_filter=None):
        """Return info about the virtual machines associated to the infrastructure."""
        pass

    @abstractmethod
    def vm(self, id_, show_output=True):
        """Return info about the specific virtual machine associated to the infrastructure."""
        pass


class CommanderIM(Commander):

    """Commander interface for Infrastructure Manager REST API.

    Ref: http://imdocs.readthedocs.io/en/devel/REST.html
    """

    def __init__(self, config, target_name, infrastructure_name, infrastructure_id=None):
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

    def __select_interface(self, system, vm_number=-1):
        """Select the ip of an interface from the available interfaces.

        Returns: 
            str, the interface ip
        """
        print(system)
        print(system.getNumNetworkIfaces())
        print(system.getRequestedNameIface())

        num_interfaces = system.getNumNetworkIfaces()

        assert num_interfaces > 0, "This vm doesn't have network interfaces..."

        if num_interfaces > 1:
            interfaces = []

            for idx in range(system.getNumNetworkIfaces()):
                interfaces.append(system.getIfaceIP(idx))
            show(
                colored("[Discovery]", "magenta"),
                colored("[{}]".format(self.__in_name), "white"),
                colored("[{}]".format(self.__target_name), "red"),
                colored("[vm_{}]".format(vm_number), "green"),
                colored("[interfaces]", "green"),
                colored("[\n{}\n]".format(
                    print_right_shift(
                        "\n".join(["-({}) {}".format(idx, elm)
                                   for idx, elm in enumerate(interfaces)])
                    )
                ), "blue")
            )
            selected_interface = int(input("[Select and interface]: "))
            return interfaces[selected_interface]

        else:
            return system.getIfaceIP(0)

    def ssh(self, url, user, vm_number, use_bastion):
        vm_info = self.info(show_output=False)
        max_vm_num_id = max(vm_info)

        assert vm_number >= 0 and vm_number <= max_vm_num_id, "VM id number out of index"

        selected_vm = self.vm(vm_number, show_output=False)
        ip = self.__select_interface(selected_vm.systems[0], vm_number)
        username, password, public_key, private_key = selected_vm.systems[0].getCredentialValues(
        )

        print(ip, username, password, public_key, private_key)

        with SSHHandler(ip, user, username, password, public_key, private_key) as cur_shell:
            stdin, stdout, stderr = cur_shell.exec("pwd")
            print(stdout.readlines())

    @property
    def in_id(self):
        if self.__in_id is not None:
            return self.__in_id
        raise Exception("You have no ID yet for this infrastructure...")

    def __url_compose(self, *args):
        if len(args):
            return "{}/{}".format(self.__server_url, "/".join(args))
        return self.__server_url

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

    def create(self, name, data_path=None, show_output=True):
        token = self.__auth.token(show_output=show_output)
        self.__header_compose(token, additional_headers={
            'Content-type': "text/yaml"
        })

        if show_output:
            show(
                colored("[Discovery]", "magenta"),
                colored("[{}]".format(self.__in_name), "white"),
                colored("[{}]".format(self.__target_name), "red"),
                colored("[CREATING] ...", "yellow")
            )

        with open(data_path, 'rb') as template_file:
            res = requests.post(
                self.__url_compose(),
                headers=self.__headers,
                data=template_file
            )

        content, result = self.__prepare_result(res, get_content=True)

        try:
            self.__in_id = extract_in_id(content['uri'])
        except TypeError:
            self.__in_id = extract_in_id(content)

        if show_output:
            show(
                colored("[Discovery]", "magenta"),
                colored("[{}]".format(self.__in_name), "white"),
                colored("[{}]".format(self.__target_name), "red"),
                colored("[CREATE]", "green"),
                colored("[\n{}\n]".format(result), "blue")
            )

    def delete(self, show_output=True):
        token = self.__auth.token(show_output=show_output)

        self.__header_compose(token)

        if show_output:
            show(
                colored("[Discovery]", "magenta"),
                colored("[{}]".format(self.__in_name), "white"),
                colored("[{}]".format(self.__target_name), "red"),
                colored("[DELETING] ...", "yellow")
            )

        res = requests.delete(
            self.__url_compose(self.in_id),
            headers=self.__headers
        )

        result = self.__prepare_result(res)

        if show_output:
            show(
                colored("[Discovery]", "magenta"),
                colored("[{}]".format(self.__in_name), "white"),
                colored("[{}]".format(self.__target_name), "red"),
                colored("[DELETE]", "green"),
                colored("[\n{}\n]".format(result), "blue")
            )

        if res.status_code == 200:
            return True

        return False

    def radl(self, show_output=True, output_filter=None):
        self.__property_name('radl', show_output=show_output,
                             output_filter=output_filter)

    def state(self, show_output=True, output_filter=None):
        return self.__property_name('state', show_output=show_output, output_filter=output_filter).json()

    def contmsg(self, show_output=True, output_filter=None):
        self.__property_name(
            'contmsg', show_output=show_output, output_filter=output_filter)

    def outputs(self, show_output=True, output_filter=None):
        self.__property_name(
            'outputs', show_output=show_output, output_filter=output_filter)

    def data(self, show_output=True, output_filter=None):
        self.__property_name('data', show_output=show_output,
                             output_filter=output_filter)

    def __prepare_result(self, res, output_filter=None, get_content=False):
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

        if get_content:
            return content, result

        return result

    def __property_name(self, property_, force=False, show_output=True, output_filter=None):
        """Get the infrastructure state.

        API REST:
            GET: http://imserver.com/infrastructures/<infId>/["radl"|"state"|"contmsg"|"outputs"|"data"]
        """
        token = self.__auth.token(force=force)
        self.__header_compose(token)

        res = requests.get(
            self.__url_compose(self.in_id, property_),
            headers=self.__headers
        )

        result = self.__prepare_result(res, output_filter=output_filter)

        if show_output:
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

        return res

    def info(self, show_output=True, output_filter=None):
        """Get information about the vms of the infrastructure.

        Print a list of URIs referencing the virtual machines associated to the
        infrastructure with ID and return a list of vm ids.
        """
        token = self.__auth.token(show_output=show_output)
        self.__header_compose(token)

        res = requests.get(
            self.__url_compose(self.in_id),
            headers=self.__headers
        )

        result = self.__prepare_result(res, output_filter=output_filter)

        if show_output:
            show(
                colored("[Discovery]", "magenta"),
                colored("[{}]".format(self.__in_name), "white"),
                colored("[{}]".format(self.__target_name), "red"),
                colored("[info]", "green"),
                colored("[\n{}\n]".format(result), "blue")
            )

        tmp = []

        for line in result.split("\n"):
            if line.find(self.in_id) != -1:
                tmp.append(line.split("/")[-1].strip())

        return [int(elm) for elm in tmp]

    def reconfigure(self, show_output=True):
        """Reconfigure the whole infrastructure."""
        token = self.__auth.token(show_output=show_output)
        self.__header_compose(token)

        res = requests.put(
            self.__url_compose(self.in_id, 'reconfigure'),
            headers=self.__headers
        )

        result = self.__prepare_result(res)

        if show_output:
            show(
                colored("[Discovery]", "magenta"),
                colored("[{}]".format(self.__in_name), "white"),
                colored("[{}]".format(self.__target_name), "red"),
                colored("[reconfigure]", "green"),
                colored("[\n{}\n]".format(result), "blue")
            )

    def vm(self, id_, contmsg=False, show_output=True):
        """Get information about the selected vm in the current infrastructure.

        Print vm info and return radl object.
        """
        token = self.__auth.token(show_output=show_output)
        self.__header_compose(token)

        if not contmsg:
            tmp = [self.in_id, 'vms', str(id_)]
        else:
            tmp = [self.in_id, 'vms', str(id_), 'contmsg']

        res = requests.get(
            self.__url_compose(*tmp),
            headers=self.__headers
        )

        result = self.__prepare_result(res)

        if show_output:
            show(
                colored("[Discovery]", "magenta"),
                colored("[{}]".format(self.__in_name), "white"),
                colored("[{}]".format(self.__target_name), "red"),
                colored("[info]", "green"),
                colored("[\n{}\n]".format(result), "blue")
            )

        if contmsg is None:
            radl_obj = parse_radl(res.text)
            return radl_obj
