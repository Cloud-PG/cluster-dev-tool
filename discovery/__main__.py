import argparse

def main():
    parser = argparse.ArgumentParser(
        prog='discovery', argument_default=argparse.SUPPRESS)
    
    args, _ = parser.parse_known_args()

if __name__ == "__main__":
    main()