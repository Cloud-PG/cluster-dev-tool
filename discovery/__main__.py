import argparse
import json

from termcolor import colored

from .utils import show


def print_list(list_):
    return "[\n{}\n]".format(
        "\n".join(
            ["  - {}".format(elm) for elm in list_]
        )
    )


def print_json_data(data):
    return "[\n{}\n]".format(json.dumps(data, indent=2))


def main():
    parser = argparse.ArgumentParser(
        prog='discovery', argument_default=argparse.SUPPRESS)

    parser.add_argument('inventory', metavar="filename",
                        default=None, help='Configuration of infrastuctures and entrypoints')
    parser.set_defaults(cmd=None)

    subparsers = parser.add_subparsers(help='Cluster setup commands')

    parser_commander = subparsers.add_parser(
        'commander', help='explore inventory commander')
    parser_commander.set_defaults(cmd="commander")
    parser_commander.add_argument(
        'commander_command', metavar="command", choices=['ls'], default="ls",
        type=str, help='Command to execute with commander resources. Possible values:["ls"]')

    parser_infrastructure = subparsers.add_parser(
        'infrastructure', help='explore inventory infrastructure')
    parser_infrastructure.set_defaults(cmd="infrastructure")
    parser_infrastructure.add_argument(
        'infrastructure_command', metavar="command", choices=['ls', 'show'], default="ls",
        type=str, help='Command to execute with infrastructure resources. Possible values:["ls"]')

    args, _ = parser.parse_known_args()

    with open(args.inventory) as inventory_file:
        inventory = json.load(inventory_file)

    # RUN
    if args.cmd == "commander":
        if args.commander_command == 'ls':
            show(
                colored("[Discovery]", "magenta"),
                colored("[commander]", "cyan", attrs=['bold']),
                colored("[ls]", "green"),
                colored(print_list(inventory['commanders'].keys()), "blue")
            )
    elif args.cmd == "infrastructure":
        if args.infrastructure_command == 'ls':
            show(
                colored("[Discovery]", "magenta"),
                colored("[infrastructure]", "cyan", attrs=['bold']),
                colored("[ls]", "green"),
                colored(print_list(
                        inventory['infrastructures'].keys()), "blue")
            )
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
