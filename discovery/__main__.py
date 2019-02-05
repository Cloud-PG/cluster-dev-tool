import argparse
import arghelper
import json

from termcolor import colored

from .commander import CommanderIM
from .utils import print_json_data, print_list, show


def get_context(target, infrastructure, commanders):
    show(
        colored("[Discovery]", "magenta"),
        colored("[{}]".format(infrastructure['commander']), "white"),
        colored("[{}]".format(target), "red"),
        colored("[get context]", "yellow", attrs=['bold']),
        colored("[{}]".format(infrastructure['id']), "yellow")
    )
    if infrastructure['commander'] in commanders:
        commander_cfg = commanders[infrastructure['commander']]
        if commander_cfg['type'] == 'IM':
            context = CommanderIM(
                commander_cfg, target, infrastructure['commander'], infrastructure['id'])
            show(
                colored("[Discovery]", "magenta"),
                colored("[{}]".format(infrastructure['commander']), "white"),
                colored("[{}]".format(target), "red"),
                colored("[get context]", "green"),
                colored("[{}]".format(infrastructure['id']), "green")
            )
            return context
    else:
        raise Exception("Commander '{}' not available in the inventory...".format(
            infrastructure['commander']))


def show_commander(target, commanders):
    if target == 'all':
        show(
            colored("[Discovery]", "magenta"),
            colored("[commander]", "cyan", attrs=['bold']),
            colored(print_list(commanders.keys()), "blue")
        )
    elif target in commanders:
        show(
            colored("[Discovery]", "magenta"),
            colored("[commander]", "cyan", attrs=['bold']),
            colored("[{}]".format(target), "yellow", attrs=['bold']),
            colored(print_json_data(commanders[target]), "blue")
        )


def list_infrastructures(target, infrastructures):
    if target == 'all':
        show(
            colored("[Discovery]", "magenta"),
            colored("[infrastructure]", "cyan", attrs=['bold']),
            colored("[show]", "green"),
            colored(print_list(infrastructures.keys()), "blue")
        )
    elif target in infrastructures:
        show(
            colored("[Discovery]", "magenta"),
            colored("[infrastructure]", "cyan", attrs=['bold']),
            colored("[show]", "green"),
            colored("[{}]".format(target), "yellow", attrs=['bold']),
            colored(print_json_data(infrastructures[target]), "blue")
        )
    else:
        show(
            colored("[Discovery]", "magenta"),
            colored("[Infrastructure]", "white"),
            colored("[{}][not found...]".format(
                target), "red")
        )


def main():
    parser = argparse.ArgumentParser(
        prog='discovery', argument_default=argparse.SUPPRESS)

    ##
    # discovery inventory
    parser.add_argument('inventory', metavar="filename",
                        default=None, help='Configuration of infrastuctures and entrypoints')

    ##
    # discovery inventory sub_command
    subparsers = parser.add_subparsers(
        help='Cluster setup commands', dest="sub_command")

    ##
    # discovery inventory sub_command sub_parser_command

    # sub command [commander]
    parser_commander = subparsers.add_parser(
        'commander', help='Explore inventory commander')
    parser_commander.add_argument(
        'commander_target', metavar="target", default="None",
        type=str, help='Target commander. It\'s the commander name.')
    sub_parser_commander = parser_commander.add_subparsers(
        dest="sub_command_commander")
    # infrastructures
    parser_infrastructure_info = sub_parser_commander.add_parser(
        'infrastructures', help='Get info about the infrastructures managed by this commander')

    # sub command [infrastructure]
    parser_infrastructure = subparsers.add_parser(
        'infrastructure', help='Explore inventory infrastructure')
    parser_infrastructure.add_argument(
        'infrastructure_target', metavar="target", default="None",
        type=str, help='Target infrastructures. It\'s the name given to that infrastructure.')
    sub_parser_infrastructure = parser_infrastructure.add_subparsers(
        dest="sub_command_infrastructure")
    # info
    parser_infrastructure_info = sub_parser_infrastructure.add_parser(
        'info', help='Get info about the infrastructure')
    # reconfigure
    parser_infrastructure_reconfigure = sub_parser_infrastructure.add_parser(
        'reconfigure', help='Reconfigure the infrastructure')
    # delete
    parser_infrastructure_delete = sub_parser_infrastructure.add_parser(
        'delete', help='Delete an infrastructures')
    # create
    parser_infrastructure_create = sub_parser_infrastructure.add_parser(
        'create', help='Create an new infrastructures')
    parser_infrastructure_create.add_argument(
        'parser_infrastructure_create_target_data_path', metavar="data_path",
        type=arghelper.extant_file, help='The template to use. This have to be an existing file.')
    parser_infrastructure_create.add_argument(
        'parser_infrastructure_create_target_commander', metavar="commander",
        type=str, help='The name of the commander to use.')
    # vm
    parser_infrastructure_vm = sub_parser_infrastructure.add_parser(
        'vm', help='Get infrastructure vm info')
    parser_infrastructure_vm.add_argument(
        'parser_infrastructure_vm_number', metavar="number",
        type=int, help='Number of vm to be inspected.')
    parser_infrastructure_vm.add_argument(
        '--vm-property', metavar="vm_property_name", default='None',
        type=str, choices=['contmsg', 'pkey', 'user'], help='Get a specific property of the selected vm.')
    parser_infrastructure_vm.add_argument(
        '--export-credentials', default=False, action="store_true", help='Export credentials of the selected vm.')

    # ssh
    parser_infrastructure_ssh = sub_parser_infrastructure.add_parser(
        'ssh', help='Use ssh commands')
    parser_infrastructure_ssh.add_argument(
        'parser_infrastructure_ssh_mode', metavar="connection_mode",
        type=str, help='How do you want to connect to the vm. Possible values are: "direct", "bastion", "vm_number".')
    parser_infrastructure_ssh.add_argument(
        'parser_infrastructure_ssh_vm_number', metavar="vm_number",
        type=int, help='Number of vm to be invoked.')

    # sub command [radl, state, contmsg, outputs, data]
    for property_ in ["radl", "state", "contmsg", "outputs", "data"]:
        cur_parser_infrastructure_property = sub_parser_infrastructure.add_parser(
            property_, help='Property {} of the infrastructures'.format(property_))
        cur_parser_infrastructure_property.add_argument('--filter', metavar="filter",
                                                        type=str, choices=['ansible_errors', 'squeezed_ansible_errors', 'infrastructure_ids'], help='Filter for command {}'.format(property_))

    args, _ = parser.parse_known_args()

    ##
    # OUTPUT TEST - to be removed...
    # print(args)

    with open(args.inventory) as inventory_file:
        inventory = json.load(inventory_file)

    # RUN
    if args.sub_command == "commander":
        cur_target = args.commander_target
        if (cur_target != 'None' or cur_target == 'list') and not args.sub_command_commander:
            show_commander(cur_target if cur_target != 'list' else 'all', inventory['commanders'])
        elif args.sub_command_commander == 'infrastructures':
            ctx = get_context("commander", {
                            'commander': cur_target,
                            'id': None
                        }, inventory['commanders'])
            ctx.infrastructures(inventory['infrastructures'])
        else:
            parser.print_help()
    elif args.sub_command == "infrastructure":
        cur_target = args.infrastructure_target
        if cur_target in inventory['lock']:
            show(
                colored("[Discovery]", "magenta"),
                colored("[Infrastructure]", "white"),
                colored("[{}][LOCKED]".format(cur_target), "red")
            )
            exit()
        elif cur_target == "list":
            list_infrastructures('all', inventory['infrastructures'])
        else:
            if args.sub_command_infrastructure == 'create':
                if args.parser_infrastructure_create_target_commander in inventory['commanders']:
                    if cur_target not in inventory['infrastructures']:
                        ctx = get_context(cur_target, {
                            'commander': args.parser_infrastructure_create_target_commander,
                            'id': None
                        }, inventory['commanders'])
                        res = ctx.create(
                            cur_target, args.parser_infrastructure_create_target_data_path)
                        if res:
                            inventory['infrastructures'][cur_target] = {
                                'commander': args.parser_infrastructure_create_target_commander,
                                'id': ctx.in_id
                            }
                            with open(args.inventory, 'w') as inventory_file:
                                json.dump(inventory, inventory_file, indent=2)
                            show(
                                colored("[Discovery]", "magenta"),
                                colored("[Infrastructure]", "white"),
                                colored("[{}][successfully created. Inventory is updated...]".format(
                                    cur_target), "green")
                            )
                        else:
                            show(
                                colored("[Discovery]", "magenta"),
                                colored("[Commander]", "white"),
                                colored("[{}][CREATION FAILED... Check the output for debuggin...]".format(
                                    args.parser_infrastructure_create_target_commander), "red")
                            )
                    else:
                        show(
                            colored("[Discovery]", "magenta"),
                            colored("[Commander]", "white"),
                            colored("[{}][already exists...]".format(
                                args.parser_infrastructure_create_target_commander), "red")
                        )
                else:
                    show(
                        colored("[Discovery]", "magenta"),
                        colored("[Commander]", "white"),
                        colored("[{}][not found...]".format(
                            args.parser_infrastructure_create_target_commander), "red")
                    )
            elif cur_target in inventory['infrastructures']:
                if args.sub_command_infrastructure in ['info', 'radl', 'state', 'contmsg', 'outputs', 'data', 'reconfigure', 'vm']:
                    ctx = get_context(
                        cur_target, inventory['infrastructures'][cur_target], inventory['commanders'])
                    method_to_call = getattr(
                        ctx, args.sub_command_infrastructure)
                    if 'filter' in args:  # for 'radl', 'state', 'contmsg', 'outputs', 'data' commands
                        method_to_call(output_filter=args.filter)
                    elif 'parser_infrastructure_vm_number' in args:  # for 'vm' command
                        method_to_call(args.parser_infrastructure_vm_number,
                                       property_=args.vm_property,
                                       export_credentials=args.export_credentials)
                    else:
                        method_to_call()
                elif args.sub_command_infrastructure == 'delete':
                    if cur_target in inventory['infrastructures']:
                        ctx = get_context(
                            cur_target, inventory['infrastructures'][cur_target], inventory['commanders'])
                        if ctx.delete():
                            del inventory['infrastructures'][cur_target]
                            with open(args.inventory, 'w') as inventory_file:
                                json.dump(inventory, inventory_file, indent=2)
                            show(
                                colored("[Discovery]", "magenta"),
                                colored("[Infrastructure]", "white"),
                                colored("[{}][successfully deleted. Inventory is updated...]".format(
                                    cur_target), "green")
                            )
                        else:
                            show(
                                colored("[Discovery]", "magenta"),
                                colored("[Infrastructure]", "white"),
                                colored("[{}][was not deleted successfully...]".format(
                                    cur_target), "red")
                            )
                    else:
                        show(
                            colored("[Discovery]", "magenta"),
                            colored("[Infrastructure]", "white"),
                            colored("[{}][not found...]".format(
                                cur_target), "red")
                        )
                elif args.sub_command_infrastructure == 'ssh':
                    cur_commander = inventory['infrastructures'][cur_target]['commander']
                    if cur_commander in inventory['commanders']:
                        cur_commander_info = inventory['commanders'][cur_commander]
                        ctx = get_context(
                            cur_target, inventory['infrastructures'][cur_target], inventory['commanders'])
                        ctx.ssh(
                            args.parser_infrastructure_ssh_mode,
                            args.parser_infrastructure_ssh_vm_number,
                            bastion=cur_commander_info['bastion'] if 'bastion' in cur_commander_info else None
                        )
                    else:
                        show(
                            colored("[Discovery]", "magenta"),
                            colored("[Commander]", "white"),
                            colored("[{}][not found...]".format(
                                cur_commander), "red")
                        )
                else:
                    list_infrastructures(
                        cur_target, inventory['infrastructures'])
            else:
                if cur_target not in inventory['infrastructures']:
                    show(
                        colored("[Discovery]", "magenta"),
                        colored("[Infrastructure]", "white"),
                        colored("[{}][not a valid target...]".format(
                            cur_target), "red")
                    )
                else:
                    show(
                        colored("[Discovery]", "magenta"),
                        colored("[Infrastructure]", "white"),
                        colored("[{}][not a valid command...]".format(
                            cur_target), "red")
                    )
                    parser.print_help()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
