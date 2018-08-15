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


def strip_error_line(line, lenght=80):
    if len(line) > lenght:
        return line[0:40] + " [...] " + line[-35:-1]
    else:
        return line


def extract_in_id(url):
    return url.split("/")[-1].strip()



def filter_output(text, filter_type, max_error_lines=8, max_lenght_error_line=1024):
    if filter_type.find("ansible_errors") != -1:
        squeeze = False
        if filter_type == "squeezed_ansible_errors":
            squeeze = True
        output = []
        in_error = False
        counter = 0
        lines = text.split("\n")
        for idx, line in enumerate(lines):
            if not in_error:
                if line.lower().find("fatal:") == 0:
                    in_error = True
                    counter = 0
                    output.append(lines[idx-1])
                    output.append(lines[idx])
                    if squeeze:
                        output[-1] = strip_error_line(output[-1],
                                                      max_lenght_error_line)
                        output[-2] = strip_error_line(output[-2],
                                                      max_lenght_error_line)
                elif line.lower().find("error") == 0:
                    in_error = True
                    counter = 0
                    output.append(lines[idx])
                    if squeeze:
                        output[-1] = strip_error_line(output[-1],
                                                      max_lenght_error_line)
            else:
                if line.lower().find("ok:") == 0 or\
                        line.lower().find("changed:") == 0 or\
                        line.lower().find("skipping:") == 0:
                    in_error = False
                    del output[-1]
                elif line.lower().find("play recap") == 0:
                    in_error = False
                else:
                    if squeeze and counter < max_error_lines:
                        counter += 1
                        output.append(lines[idx])
                        if squeeze:
                            output[-1] = strip_error_line(
                                output[-1], max_lenght_error_line)
                    else:
                        in_error = False
        return "\n".join(output)
    else:
        raise Exception(
            "Filter '{}' is not implemented...".format(filter_type))
