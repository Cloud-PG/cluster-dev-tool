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
    sub_parser_infrastructure = parser_infrastructure.add_subparsers(
        dest="sub_command_infrastructure")
    parser_infrastructure_show = sub_parser_infrastructure.add_parser(
        'show', help='Get info about infrastructures')
    parser_infrastructure_show.add_argument(
        'parser_infrastructure_show_target', metavar="target",
        type=str, help='Target of show command for infrastructures. Possible values: ["all", infrastructure_id]')
    parser_infrastructure_delete = sub_parser_infrastructure.add_parser(
        'delete', help='Delete an infrastructures')
    parser_infrastructure_delete.add_argument(
        'parser_infrastructure_delete_target', metavar="target",
        type=str, help='Target of delete command for infrastructures. It\'s the name given to that infrastructure.')
    parser_infrastructure_create = sub_parser_infrastructure.add_parser(
        'create', help='Create an new infrastructures')
    parser_infrastructure_create.add_argument(
        'parser_infrastructure_create_target_name', metavar="name",
        type=str, help='The name of the new infrastructures.')
    parser_infrastructure_create.add_argument(
        'parser_infrastructure_create_target_commander', metavar="commander",
        type=str, help='The name of the commander to use.')
    parser_infrastructure_create.add_argument(
        'parser_infrastructure_create_target_data_path', metavar="data_path",
        type=arghelper.extant_file, help='The template to use. This have to be an existing file.')

    # sub command [radl, state, contmsg, outputs, data]
    for property_ in ["radl", "state", "contmsg", "outputs", "data"]:
        cur_parser_infrastructure_property = sub_parser_infrastructure.add_parser(
            property_, help='Property {} of the infrastructures'.format(property_))
        cur_parser_infrastructure_property.add_argument(
            'parser_{}_target'.format(property_), metavar="target",
            type=str, help='Target of command {}'.format(property_))
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
            if not command_show(args.sub_command, args.parser_commander_show_target, inventory['commanders']):
                parser.print_help()
        else:
            parser.print_help()
    elif args.sub_command == "infrastructure":
        if args.sub_command_infrastructure == 'show':
            if not command_show(args.sub_command, args.parser_infrastructure_show_target, inventory['infrastructures']):
                parser.print_help()
        elif args.sub_command_infrastructure == 'delete':
            cur_target = args.parser_infrastructure_delete_target
            if args.parser_infrastructure_delete_target in inventory['infrastructures']:
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
                            args.parser_infrastructure_delete_target), "green")
                    )
                else:
                    show(
                        colored("[Discovery]", "magenta"),
                        colored("[Infrastructure]", "white"),
                        colored("[{}][was not deleted successfully...]".format(
                            args.parser_infrastructure_delete_target), "red")
                    )
            else:
                show(
                    colored("[Discovery]", "magenta"),
                    colored("[Infrastructure]", "white"),
                    colored("[{}][not found...]".format(
                        args.parser_infrastructure_delete_target), "red")
                )
        elif args.sub_command_infrastructure == 'create':
            cur_target = args.parser_infrastructure_create_target_name
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
        elif args.sub_command_infrastructure in ["radl", "state", "contmsg", "outputs", "data"]:
            tmp = 'parser_{}_target'.format(args.sub_command_infrastructure)
            cur_target = getattr(args, tmp)
            if cur_target in inventory['infrastructures']:
                ctx = get_context(
                    cur_target, inventory['infrastructures'][cur_target], inventory['commanders'])
                getattr(ctx, args.sub_command_infrastructure)(
                    output_filter=args.filter)
            else:
                show(
                    colored("[Discovery]", "magenta"),
                    colored("[Infrastructure]", "white"),
                    colored("[{}][not found...]".format(
                        args.parser_infrastructure_delete_target), "red")
                )
        else:
            parser.print_help()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
