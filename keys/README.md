Public and private keys used by fence should go in this directory.

Don't make any subdirectories here that don't contain JWT public and private key
PEM files; otherwise fence will raise an error when it tries to load the keys
from this directory at startup.
