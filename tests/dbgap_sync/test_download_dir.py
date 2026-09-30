"""
`download_dir` copies files off a remote SFTP server, so every filename it receives is
untrusted input. A malicious or compromised server can answer a directory listing with
path separators or an absolute path, which must not redirect the local write.
"""

import os
from stat import S_IFDIR, S_IFREG

import pytest

from fence.sync.sync_users import download_dir


class FakeSFTPAttributes(object):
    """Stand-in for paramiko's SFTPAttributes carrying only what `download_dir` reads."""

    def __init__(self, filename: str, is_dir: bool = False) -> None:
        self.filename = filename
        self.st_mode = (S_IFDIR if is_dir else S_IFREG) | 0o644


class FakeSFTPClient(object):
    """
    Minimal SFTP client that serves a scripted listing and records local writes.

    `get` writes real bytes so that a traversal which escapes the download directory
    leaves observable evidence on disk rather than only showing up in an assertion.
    """

    def __init__(self, listings: dict) -> None:
        self.listings = listings
        self.written = []

    def listdir_attr(self, remote_dir: str) -> list:
        return self.listings.get(remote_dir, [])

    def get(self, remote_path: str, local_path: str) -> None:
        self.written.append(local_path)
        # paramiko does not create missing parents; this harness does so that a
        # traversal into a subdirectory is observable as a write rather than an
        # unrelated FileNotFoundError.
        os.makedirs(os.path.dirname(local_path), exist_ok=True)
        with open(local_path, "wb") as local_file:
            local_file.write(b"payload")


def _is_inside(path: str, directory: str) -> bool:
    """Whether `path` resolves to a location within `directory`."""
    resolved_dir = os.path.realpath(directory)
    return os.path.realpath(path).startswith(resolved_dir + os.sep)


@pytest.fixture
def local_dir(tmp_path):
    """An existing, empty download destination."""
    destination = tmp_path / "download"
    destination.mkdir()
    return destination


def test_benign_filename_is_downloaded(local_dir):
    """An ordinary filename is still fetched into the download directory."""
    sftp = FakeSFTPClient({"./": [FakeSFTPAttributes("telemetry.csv")]})

    download_dir(sftp, "./", str(local_dir))

    assert (local_dir / "telemetry.csv").read_bytes() == b"payload"


def test_absolute_remote_filename_cannot_escape(tmp_path, local_dir):
    """An absolute filename from the server does not relocate the write."""
    escape_target = tmp_path / "escaped_absolute"
    sftp = FakeSFTPClient({"./": [FakeSFTPAttributes(str(escape_target))]})

    download_dir(sftp, "./", str(local_dir))

    assert not escape_target.exists()
    assert all(_is_inside(path, str(local_dir)) for path in sftp.written)


def test_relative_traversal_cannot_escape(tmp_path, local_dir):
    """A `..` sequence in a server-supplied filename does not escape the directory."""
    escape_target = tmp_path / "escaped_relative"
    sftp = FakeSFTPClient(
        {"./": [FakeSFTPAttributes("../../download/../escaped_relative")]}
    )

    download_dir(sftp, "./", str(local_dir))

    assert not escape_target.exists()
    assert all(_is_inside(path, str(local_dir)) for path in sftp.written)


def test_traversing_directory_entry_cannot_escape(tmp_path, local_dir):
    """A traversing directory entry does not place its children outside the directory."""
    sftp = FakeSFTPClient(
        {
            "./": [FakeSFTPAttributes("../escaped_dir", is_dir=True)],
            ".//../escaped_dir": [FakeSFTPAttributes("payload.csv")],
        }
    )

    download_dir(sftp, "./", str(local_dir))

    assert not (tmp_path / "escaped_dir").exists()
    assert all(_is_inside(path, str(local_dir)) for path in sftp.written)


def test_hostile_entry_does_not_prevent_benign_download(tmp_path, local_dir):
    """A rejected entry is skipped without aborting the rest of the listing."""
    escape_target = tmp_path / "escaped_absolute"
    sftp = FakeSFTPClient(
        {
            "./": [
                FakeSFTPAttributes(str(escape_target)),
                FakeSFTPAttributes("telemetry.csv"),
            ]
        }
    )

    download_dir(sftp, "./", str(local_dir))

    assert not escape_target.exists()
    assert (local_dir / "telemetry.csv").read_bytes() == b"payload"
