import sys


def print_progress(progress: int) -> None:
    print(f"trigger:progress:{progress}")
    sys.stdout.flush()


def print_output(output: str) -> None:
    print(f"trigger:output:{output}")
    sys.stdout.flush()
