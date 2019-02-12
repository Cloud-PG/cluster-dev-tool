import configparser
import json
import signal
import socket
import tempfile
from abc import ABCMeta, abstractmethod
from getpass import getpass
from os import chmod
from time import sleep

import paramiko
import requests
from radl.radl_parse import parse_radl
from termcolor import colored
from yaspin import Spinner, yaspin
from yaspin.spinners import Spinners

from .auth import IAM
from .utils import (extract_in_id, filter_output, print_json_data, print_list,
                    print_right_shift, show)

DISCOVERY_SPINNER = Spinner([
    "[=        ]",
    "[==       ]",
    "[===      ]",
    "[====     ]",
    "[=====    ]",
    "[ =====   ]",
    "[  =====  ]",
    "[   ===== ]",
    "[    =====]",
    "[     ====]",
    "[      ===]",
    "[       ==]",
    "[        =]",
    "[       ==]",
    "[      ===]",
    "[     ====]",
    "[    =====]",
    "[   ===== ]",
    "[  =====  ]",
    "[ =====   ]",
    "[=====    ]",
    "[====     ]",
    "[===      ]",
    "[==       ]"
], 80)


class KeyFile(object):

    def __init__(self, content):
        self.__file = tempfile.NamedTemporaryFile(mode="w")
        self.__file.write(content)
        self.__file.flush()
        self.__file.seek(0)

    @property
    def name(self):
        return self.__file.name

    def __enter__(self):
        return self.__file

    def __exit__(self, type_, value, traceback):
        pass

    def __del__(self):
        self.__file.close()


class SSHHandler(object):

    def __init__(self, ip, username, password=None, public_key=None, private_key=None):
        self.__ip = ip
        self.__username = username
        self.__password = password
        self.__public_key = KeyFile(public_key) if public_key else public_key
        self.__private_key = KeyFile(
            private_key) if private_key else private_key
        self.__ssh = paramiko.SSHClient()
        self.__ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.__channel = None

    def __connect(self):
        show(
            colored("[Discovery]", "magenta"),
            colored("[vm]", "white"),
            colored("[{}]".format(self.__ip), "cyan")
        )
        if not self.__private_key and not self.__password:
            password = getpass(
                "[Insert User {} password...]".format(self.__username))
            self.__ssh.connect(
                self.__ip, username=self.__username, password=password)
        elif self.__password:
            self.__ssh.connect(self.__ip, username=self.__username,
                               password=self.__password)
        elif self.__private_key:
            tmp_key = paramiko.RSAKey.from_private_key_file(
                self.__private_key.name)
            self.__ssh.connect(self.__ip, username=self.__username,
                               pkey=tmp_key,
                               look_for_keys=False,
                               allow_agent=False)
        else:
            raise Exception("Can't connect with a valid method...")

    def __enter__(self):
        self.__connect()
        return self

    def __exit__(self, type_, value, traceback):
        self.__ssh.close()

    def __del__(self):
        del self.__public_key
        del self.__private_key

    def exec(self, command):
        stdin, stdout, stderr = self.__ssh.exec_command(command)
        return stdin, stdout, stderr

    def __recv(self, timeout=1.0, size=1024, attempts=5, sleep_time=0.2):
        self.__channel.settimeout(timeout)
        buffer = b""
        for _ in range(attempts):
            try:
                while self.__channel.recv_ready():
                    sleep(sleep_time)
                    buffer += self.__channel.recv(size)
            except socket.timeout:
                pass
            sleep(sleep_time)

        return buffer.decode("utf-8")

    def jump(self, ip, username, password=None, public_key=None, private_key=None):
        if self.__channel is None:
            self.__channel = self.__ssh.invoke_shell()
        if password:
            show(
                colored("[Discovery][ssh]", "magenta"),
                colored("[Found password login]", "green")
            )
            commands = [
                ("ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no {}@{}\n".format(
                    username, ip), "open shell"),
                (password + "\n", "insert password")
            ]
        elif private_key:
            show(
                colored("[Discovery][ssh]", "magenta"),
                colored("[Found private key login]", "green")
            )
            commands = [
                ("cat << EOF > p.key\n{}\nEOF\n".format(private_key), "copy key"),
                ("chmod 0600 p.key\n", "change attribute"),
                ("chown cloudadm:cloudadm p.key\n", "change owner"),
                ("ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -i p.key {}@{}\n".format(
                    username, ip), "open shell with key")
            ]
        else:
            raise Exception("Not a valid credential method to jump...")
        while len(commands) > 0:
            while not self.__channel.send_ready():
                sleep(0.1)
            cur_command, message = commands.pop(0)
            show(
                colored("[Discovery][ssh]", "magenta"),
                colored("[{}]".format(message), "yellow")
            )
            self.__channel.sendall(cur_command)

    def __prepare(self):
        """Superuser escalation and open bash."""
        self.__channel.sendall("sudo -s\n")
        self.__channel.sendall("bash\n")

    def invoke_shell(self):
        run = True
        if self.__channel is None:
            self.__channel = self.__ssh.invoke_shell()
        print(self.__recv())
        self.__prepare()
        print(self.__recv())

        while run:
            input_ = ""
            try:
                input_ = input(
                    colored("[Discovery][ssh][Insert command]:", "magenta"))
            except KeyboardInterrupt:
                input_ = "discovery_exit"
            self.__channel.sendall(input_ + "\n")
            if input_ == "discovery_exit":
                run = False
            else:
                print(self.__recv())

        show(
            colored("\033[2K\r[Discovery][ssh][Session DONE]", "magenta")
        )
        self.__channel.close()


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
        self.__server_url = config['server_url'].strip()
        if self.__server_url[-1] == "/":
            self.__server_ur = self.__server_ur[:-1]
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
        # print(system)
        # print(system.getNumNetworkIfaces())
        # print(system.getRequestedNameIface())

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
            selected_interface = int(input("[Select an interface]: "))
            return interfaces[selected_interface]

        else:
            return system.getIfaceIP(0)

    def __check_vm_number(self, num):
        vm_info = self.info(show_output=False)
        max_vm_num_id = max(vm_info)

        assert num >= 0 and num <= max_vm_num_id, "VM id number out of index"

    def __get_vm_credentials(self, vm_number):
        selected_vm = self.vm(vm_number, show_output=False)

        if selected_vm:
            ip = self.__select_interface(selected_vm.systems[0], vm_number)
            credentials = selected_vm.systems[0].getCredentialValues()
            return (ip, credentials)
        else:
            show(
                colored("[Discovery]", "magenta"),
                colored("[{}]".format(self.__in_name), "white"),
                colored("[{}]".format(self.__target_name), "red"),
                colored("[vm_{}]".format(vm_number), "green"),
                colored("[is not ready...]", "yellow")
            )

    def ssh(self, mode, vm_number, bastion=None):
        self.__check_vm_number(vm_number)
        ip, (username, password, public_key,
             private_key) = self.__get_vm_credentials(vm_number)

        if mode == 'direct':
            show(
                colored("[Discovery]", "magenta"),
                colored("[{}]".format(self.__in_name), "white"),
                colored("[{}]".format(self.__target_name), "red"),
                colored("[vm_{}]".format(vm_number), "green"),
                colored("[Open ssh]", "yellow")
            )
            with SSHHandler(ip, username, password, public_key, private_key) as cur_shell:
                cur_shell.invoke_shell()
        elif mode == 'bastion':
            with SSHHandler(bastion['addr'], bastion['username']) as cur_shell:
                cur_shell.jump(ip, username, password, public_key, private_key)
                cur_shell.invoke_shell()
        else:
            proxy_vm_id = int(mode)
            proxy_ip, (proxy_username, proxy_password, proxy_public_key,
                       proxy_private_key) = self.__get_vm_credentials(proxy_vm_id)
            if proxy_private_key:
                with SSHHandler(proxy_ip, proxy_username, proxy_password, proxy_public_key,
                                proxy_private_key) as cur_shell:
                    cur_shell.jump(ip, username, password,
                                   public_key, private_key)
                    cur_shell.invoke_shell()
            else:
                raise Exception("Case not implemented yet... :P")

    @property
    def in_id(self):
        if self.__in_id is not None:
            return self.__in_id
        raise Exception("You have no ID yet for this commander...")

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
                colored("[{}]".format(self.__target_name), "red")
            )

        with open(data_path, 'rb') as template_file:
            with yaspin(DISCOVERY_SPINNER, text=colored("Creating...", "yellow"), color="yellow") as spinner:
                res = requests.post(
                    self.__url_compose('infrastructures'),
                    headers=self.__headers,
                    data=template_file
                )
                spinner.text = "\r"

            if res.status_code == 400:
                self.__error('create', res)

        content, result = self.__prepare_result(res, get_content=True)

        if show_output:
            show(
                colored("[Discovery]", "magenta"),
                colored("[{}]".format(self.__in_name), "white"),
                colored("[{}]".format(self.__target_name), "red"),
                colored("[CREATE]", "green"),
                colored("[\n{}\n]".format(result), "blue")
            )

        if res.status_code == 200:
            try:
                self.__in_id = extract_in_id(content['uri'])
            except TypeError:
                self.__in_id = extract_in_id(content)
            return True
        return False

    def delete(self, show_output=True):
        token = self.__auth.token(show_output=show_output)

        self.__header_compose(token)

        if show_output:
            show(
                colored("[Discovery]", "magenta"),
                colored("[{}]".format(self.__in_name), "white"),
                colored("[{}]".format(self.__target_name), "red")
            )

        with yaspin(DISCOVERY_SPINNER, text=colored("Deleting...", "yellow"), color="yellow") as spinner:
            res = requests.delete(
                self.__url_compose("infrastructures", self.in_id),
                headers=self.__headers
            )
            spinner.text = "\r"

        if res.status_code == 400:
            self.__error('delete', res)

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

    def state(self, show_output=True, output_filter=None, monitor=False):
        return self.__property_name('state', show_output=show_output, output_filter=output_filter, monitor=monitor).json()

    def contmsg(self, show_output=True, output_filter=None, monitor=False):
        self.__property_name(
            'contmsg', show_output=show_output, output_filter=output_filter, monitor=monitor)

    def outputs(self, show_output=True, output_filter=None):
        self.__property_name(
            'outputs', show_output=show_output, output_filter=output_filter)

    def data(self, show_output=True, output_filter=None):
        self.__property_name('data', show_output=show_output,
                             output_filter=output_filter)

    def __prepare_result(self, res, output_filter=None, get_content=False, shift=True):
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

        if shift:
            result = print_right_shift(result)

        if get_content:
            return content, result

        return result

    @staticmethod
    def __colored_contmsg(text):
        for line in text.split("\n"):
            if line.find("TASK") != -1:
                tmp = line.split("[", 1)
                content = tmp[1].rsplit("]", 1)
                head = colored("{}[".format(tmp[0]), "blue", attrs=["bold"])
                tail = colored("]{}".format(
                    content[1]), "blue", attrs=["bold"])
                try:
                    module, task = content[0].split(":", 1)
                    module = colored("{}:".format(module), "white")
                    task = colored(task, "magenta")
                except ValueError:
                    module = ""
                    task = colored(content[0], "magenta")
                yield head + module + task + tail
            elif line.find("ok: ") != -1:
                head, content = line.split(": ", 1)
                head = colored("{}: ".format(head), "green", attrs=["bold"])
                yield head + content
            elif line.find("skipping: ") != -1:
                head, content = line.split(": ", 1)
                head = colored("{}: ".format(head), "cyan")
                yield head + content
            elif line.find("changed: ") != -1:
                head, content = line.split(": ", 1)
                head = colored("{}: ".format(head), "yellow", attrs=["bold"])
                yield head + content
            elif line.find("fatal: ") != -1:
                head, content = line.split(": ", 1)
                head = colored("{}: ".format(head), "red",
                               attrs=["bold", "underline"])
                info, err = content.split("=>")
                yield head + info + "=>" + print_json_data(json.loads(err), indent=4)
            elif line.find("PLAY [") != -1:
                yield colored(line, 'white', attrs=["bold", "underline"])
            elif line.find("PLAY RECAP") != -1:
                yield colored(line, 'white', attrs=["bold", "underline"])
            else:
                yield line

    def __property_name(self, property_, force=False, show_output=True, output_filter=None, monitor=False):
        """Get the infrastructure state.

        API REST:
            GET: http://imserver.com/infrastructures/<infId>/["radl"|"state"|"contmsg"|"outputs"|"data"]
        """
        token = self.__auth.token(force=force)
        self.__header_compose(token)

        def property_request():
            res = requests.get(
                self.__url_compose(
                    "infrastructures", self.in_id, property_),
                headers=self.__headers
            )

            if res.status_code < 300 or res.status_code == 400:
                return res
            return False

        if monitor:
            if property_ == "state":
                try:
                    with yaspin(DISCOVERY_SPINNER, text=colored("Monitoring...", 'yellow'), color="yellow") as spinner:
                        for res in iter(property_request, False):
                            if res.status_code < 300:
                                obj = res.json()
                                current_state = obj['state']['state']
                                if current_state == "configured" or current_state == "unconfigured":
                                    raise KeyboardInterrupt
                                spinner.text = colored("State -> {}".format(
                                    obj['state']['state']), 'yellow')
                            elif res.status_code == 400:
                                if res.text.find("OIDC auth Token expired") != -1:
                                    show(
                                        colored(" !!! [Discovery]", "magenta"),
                                        colored("[{}]".format(
                                            self.__in_name), "white"),
                                        colored("[{}]".format(
                                            self.__target_name), "red"),
                                        colored("[{}]".format(
                                            property_), "green"),
                                        colored("[Session expired...]", "red")
                                    )
                                    exit(0)
                                else:
                                    self.__error(property_, res)
                            sleep(5)
                except KeyboardInterrupt:
                    spinner.text = "\r"
                    result = self.__prepare_result(
                        res, output_filter=output_filter)
                    show(
                        colored("[Discovery]", "magenta"),
                        colored("[{}]".format(self.__in_name), "white"),
                        colored("[{}]".format(self.__target_name), "red"),
                        colored("[{}]".format(property_), "green"),
                        colored("[\n{}\n]".format(result), "blue")
                    )
                    return res
            elif property_ == "contmsg":
                def contmgs_handler(signum, frame, spinner):
                    spinner.stop()
                    exit(0)
                spinner = yaspin(Spinners.shark, color='magenta', sigmap={signal.SIGINT: contmgs_handler})
                spinner.start()
                last_line = 1
                for res in iter(property_request, False):
                    try:
                        if res.status_code < 300:
                            result = self.__prepare_result(
                                res, output_filter=output_filter)
                            output = list(self.__colored_contmsg(result))
                            if last_line != len(output):
                                spinner.stop()
                                for line in range(last_line - 1, len(output)):
                                    sleep(0.02)
                                    print(output[line])
                                last_line = len(output)
                                spinner.start()
                        elif res.status_code == 400:
                            if res.text.find("OIDC auth Token expired") != -1:
                                show(
                                    colored(" !!! [Discovery]", "magenta"),
                                    colored("[{}]".format(
                                        self.__in_name), "white"),
                                    colored("[{}]".format(
                                        self.__target_name), "red"),
                                    colored("[{}]".format(property_), "green"),
                                    colored("[Session expired...]", "red")
                                )
                                exit(0)
                            else:
                                self.__error(property_, res)
                    except KeyboardInterrupt:
                        exit(0)
                    sleep(5)

        res = requests.get(
            self.__url_compose("infrastructures", self.in_id, property_),
            headers=self.__headers
        )

        if res.status_code == 400:
            if res.text.find("OIDC auth Token expired") != -1:
                return self.__property_name(property_, force=True)
            else:
                self.__error(property_, res)

        result = self.__prepare_result(res, output_filter=output_filter)

        if show_output:
            if property_ == "contmsg":
                show(
                    colored("[Discovery]", "magenta"),
                    colored("[{}]".format(self.__in_name), "white"),
                    colored("[{}]".format(self.__target_name), "red"),
                    colored("[{}]".format(property_), "green"),
                    colored("[\n", "blue"),
                    "\n".join(self.__colored_contmsg(result)),
                    colored("\n]", "blue")
                )
            else:
                show(
                    colored("[Discovery]", "magenta"),
                    colored("[{}]".format(self.__in_name), "white"),
                    colored("[{}]".format(self.__target_name), "red"),
                    colored("[{}]".format(property_), "green"),
                    colored("[\n{}\n]".format(result), "blue")
                )

        return res

    def info(self, show_output=True, output_filter=None):
        """Get information about the vms of the infrastructure.

        Print a list of URIs referencing the virtual machines associated to the
        infrastructure with ID and return a list of vm ids.
        """
        token = self.__auth.token(show_output=show_output)
        self.__header_compose(token)

        res = requests.get(
            self.__url_compose("infrastructures", self.in_id),
            headers=self.__headers
        )

        if res.status_code == 400:
            self.__error('info', res)

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
            self.__url_compose("infrastructures", self.in_id, 'reconfigure'),
            headers=self.__headers
        )

        if res.status_code == 400:
            self.__error('reconfigure', res)

        result = self.__prepare_result(res)

        if show_output:
            show(
                colored("[Discovery]", "magenta"),
                colored("[{}]".format(self.__in_name), "white"),
                colored("[{}]".format(self.__target_name), "red"),
                colored("[reconfigure]", "green"),
                colored("[\n{}\n]".format(result), "blue")
            )

    def vm(self, id_, property_=None, export_credentials=False, show_output=True):
        """Get information about the selected vm in the current infrastructure.

        Print vm info and return radl object.
        """
        self.__check_vm_number(id_)

        token = self.__auth.token(show_output=show_output)
        self.__header_compose(token)

        if property_ != 'contmsg':
            tmp = [self.in_id, 'vms', str(id_)]
        else:
            tmp = [self.in_id, 'vms', str(id_), 'contmsg']

        res = requests.get(
            self.__url_compose("infrastructures", *tmp),
            headers=self.__headers
        )

        if res.status_code == 400:
            self.__error('vm', res)

        radl_obj = None
        if property_ != 'contmsg':
            radl_obj = parse_radl(res.text)

        if show_output:
            if radl_obj:
                system = radl_obj.systems[0]
            if property_ == 'pkey':
                _, _, _, pkey = system.getCredentialValues()
                result = pkey
            elif property_ == 'user':
                user, _, _, _ = system.getCredentialValues()
                result = user
            elif export_credentials:
                user, _, _, pkey = system.getCredentialValues()
                ip = system.getIfaceIP(system.getNumNetworkIfaces() - 1)
                key_filename = "tmp_p.key"
                with open(key_filename, "w") as key_file:
                    key_file.write(pkey)
                chmod(key_filename, 0o600)
                command = "ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -i {} {}@{}".format(
                    key_filename, user, ip
                )
                result = "A temporari 'tmp_p.key is written. We use the following command to connect:\n\n{}\n".format(
                    command)
            else:
                result = self.__prepare_result(res)
                result = "\n{}\n".format(result)

            show(
                colored("[Discovery]", "magenta"),
                colored("[{}]".format(self.__in_name), "white"),
                colored("[{}]".format(self.__target_name), "red"),
                colored("[info]", "green"),
                colored("[\n", "blue"),
                "\n".join(self.__colored_contmsg(result)),
                colored("\n]", "blue")
            )

        if property_ != 'contmsg':
            return radl_obj

    def infrastructures(self, infrastructures, show_output=True):
        """Get all infrastructure ids which this commander has access."""
        token = self.__auth.token(show_output=show_output)
        self.__header_compose(token)

        res = requests.get(
            self.__url_compose("infrastructures"),
            headers=self.__headers
        )

        if res.status_code == 400:
            self.__error('infrastructures', res)

        result = self.__prepare_result(res, output_filter="infrastructure_ids")

        tmp_inf = [(key, value['id'])
                   for key, value in infrastructures.items()]
        for name, in_id in tmp_inf:
            if result.find(in_id) != -1:
                result = result.replace(in_id, "{} -> {}".format(in_id, name))

        if show_output:
            show(
                colored("[Discovery]", "magenta"),
                colored("[{}]".format(self.__in_name), "white"),
                colored("[infrastructures]", "red"),
                colored("[ids]", "green"),
                colored("[\n{}\n]".format(result), "blue")
            )

    def __error(self, command, res):
        show(
            colored("[Discovery]", "magenta"),
            colored("[{}]".format(self.__in_name), "white"),
            colored("[{}]".format(self.__target_name), "red"),
            colored("[{}][ERROR]".format(command), "red"),
            colored("[\n{}\n]".format(res.text), "blue")
        )
        exit()
