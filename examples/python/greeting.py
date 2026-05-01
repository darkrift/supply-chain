from pathlib import Path

from packaging.version import Version

from python.message_format import format_message


def load_salutation():
    return Path(__file__).with_name("salutation.txt").read_text().strip()


def greeting_for(name):
    runtime_version = Version("3.11.0")
    return format_message(load_salutation(), name, runtime_version)
