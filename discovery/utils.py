def show(*args, **kwargs):
    if kwargs.get('clean'):
        print('\x1b[2K', end="\r")
        kwargs.pop('clean')
    print("".join(args), **kwargs)