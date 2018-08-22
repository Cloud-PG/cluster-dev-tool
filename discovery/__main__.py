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
        colored("[get context]", "yellow", attrs=['bold'])
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
                colored("[get context]", "green")
            )
            return context
    else:
        raise Exception("Commander '{}' not available in the inventory...".format(
            infrastructure['commander']))


def command_show(sub_command, target, dict_):
    if target == 'all':
        show(
            colored("[Discovery]", "magenta"),
            colored("[{}]".format(sub_command), "cyan", attrs=['bold']),
            colored("[show]", "green"),
            colored(print_list(dict_.keys()), "blue")
        )
        return True
    elif target in dict_:
        show(
            colored("[Discovery]", "magenta"),
            colored("[infrastructure]", "cyan", attrs=['bold']),
            colored("[show]", "green"),
            colored("[{}]".format(target), "yellow", attrs=['bold']),
            colored(print_json_data(dict_[target]), "blue")
        )
        return True
    return False


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
    sub_parser_commander = parser_commander.add_subparsers(
        dest="sub_command_commander")
    parser_commander_show = sub_parser_commander.add_parser(
        'show', help='Get info about commanders')
    parser_commander_show.add_argument(
        'parser_commander_show_target', metavar="target",
        type=str, help='Target of show command for commanders. Possible values: ["all", infrastructure_id]')

    # sub command [infrastructure]
    parser_infrastructure = subparsers.add_parser(
        'infrastructure', help='Explore inventory infrastructure')
    parser_infrastructure.add_argument(
        'infrastructure_target', metavar="target",
        type=str, help='Target infrastructures. It\'s the name given to that infrastructure.')
    sub_parser_infrastructure = parser_infrastructure.add_subparsers(
        dest="sub_command_infrastructure")
    # show
    parser_infrastructure_show = sub_parser_infrastructure.add_parser(
        'show', help='Get info about infrastructures in the inventory')
    # info
    parser_infrastructure_info = sub_parser_infrastructure.add_parser(
        'info', help='Get info about the infrastructure')
    # reconfigure
    parser_infrastructure_reconfigure = sub_parser_infrastructure.add_parser(
        'reconfigure', help='Reconfigure about the infrastructure')
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
    # ssh
    parser_infrastructure_ssh = sub_parser_infrastructure.add_parser(
        'ssh', help='Use ssh commands')
    parser_infrastructure_ssh.add_argument(
        'parser_infrastructure_ssh_vm_number', metavar="vm_number",
        type=int, help='Number of vm to be invoked.')

    # sub command [radl, state, contmsg, outputs, data]
    for property_ in ["radl", "state", "contmsg", "outputs", "data"]:
        cur_parser_infrastructure_property = sub_parser_infrastructure.add_parser(
            property_, help='Property {} of the infrastructures'.format(property_))
        cur_parser_infrastructure_property.add_argument('--filter', metavar="filter",
                                                        type=str, choices=['ansible_errors', 'squeezed_ansible_errors'], help='Filter for command {}'.format(property_))

    args, _ = parser.parse_known_args()

    ##
    # OUTPUT TEST - to be removed...
    print(args)

    with open(args.inventory) as inventory_file:
        inventory = json.load(inventory_file)

    # RUN
    if args.sub_command == "commander":
        if args.sub_command_commander == 'show':
            if not command_show(args.sub_command, args.infrastructure_target, inventory['commanders']):
                parser.print_help()
        else:
            parser.print_help()
    elif args.sub_command == "infrastructure":
        cur_target = args.infrastructure_target
        if args.sub_command_infrastructure == 'create':
            if args.parser_infrastructure_create_target_commander in inventory['commanders']:
                ctx = get_context(cur_target, {
                    'commander': args.parser_infrastructure_create_target_commander,
                    'id': None
                }, inventory['commanders'])
                ctx.create(
                    cur_target, args.parser_infrastructure_create_target_data_path)
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
                    colored("[{}][not found...]".format(
                        args.parser_infrastructure_create_target_commander), "red")
                )
        elif cur_target in inventory['infrastructures']:
            if args.sub_command_infrastructure in ['info', 'radl', 'state', 'contmsg', 'outputs', 'data', 'reconfigure', 'vm']:
                ctx = get_context(
                    cur_target, inventory['infrastructures'][cur_target], inventory['commanders'])
                method_to_call = getattr(ctx, args.sub_command_infrastructure)
                if 'filter' in args:  # for 'radl', 'state', 'contmsg', 'outputs', 'data' commands
                    method_to_call(output_filter=args.filter)
                elif 'parser_infrastructure_vm_number' in args:  # for 'vm' command
                    method_to_call(args.parser_infrastructure_vm_number)
                else:
                    method_to_call()
            elif args.sub_command_infrastructure == 'show':
                if not command_show(args.sub_command, cur_target, inventory['infrastructures']):
                    parser.print_help()
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
                        colored("[{}][not found...]".format(cur_target), "red")
                    )
            elif args.sub_command_infrastructure == 'ssh':
                cur_commander = inventory['infrastructures'][cur_target]['commander']
                if cur_commander in inventory['commanders']:
                    cur_commander_info = inventory['commanders'][cur_commander]
                    if 'bastion' in cur_commander_info:
                        ctx = get_context(
                            cur_target, inventory['infrastructures'][cur_target], inventory['commanders'])
                        ctx.ssh(
                            cur_commander_info['bastion']['url'],
                            cur_commander_info['bastion']['user'],
                            args.parser_infrastructure_ssh_vm_number
                        )
                    else:
                        show(
                            colored("[Discovery]", "magenta"),
                            colored("[Commander]", "white"),
                            colored("[{}][have no bastion]".format(cur_commander), "red")
                        )
                else:
                    show(
                        colored("[Discovery]", "magenta"),
                        colored("[Commander]", "white"),
                        colored("[{}][not found...]".format(cur_commander), "red")
                    )
            else:
                parser.print_help()
        else:
            show(
                colored("[Discovery]", "magenta"),
                colored("[Infrastructure]", "white"),
                colored("[{}][not found...]".format(cur_target), "red")
            )
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
