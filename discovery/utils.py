import json


def show(*args, **kwargs):
    if kwargs.get('clean'):
        print('\x1b[2K', end="\r")
        kwargs.pop('clean')
    print("".join(args), **kwargs)


def print_list(list_):
    return "[\n{}\n]".format(
        "\n".join(
            ["  - {}".format(elm) for elm in list_]
        )
    )


def print_json_data(data):
    return json.dumps(data, indent=2)


def print_right_shift(string, n=2):
    tmp = string.split("\n")
    for idx, line in enumerate(tmp):
        tmp[idx] = "{}{}".format(" "*n, line)
    return "\n".join(tmp)
