import os


def read_file(filename):
    """Read the contents of a file in the tests directory."""
    root_dir = os.path.dirname(os.path.realpath(__file__))
    with open(os.path.join(root_dir, filename), 'r') as f:
        return f.read()
