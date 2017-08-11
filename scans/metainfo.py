import os

from core.manifest import load as load_meta
import plistlib


# todo: cache meta somewhere
def scan(directory):
    manifest = load_meta(directory)
    urls = manifest.urls

    yield Message('found following urls: \n%s' % '\n'.join(urls), extra=urls)
    yield Message('content of Info.plist', extra=manifest.dump())

    # todo: url fuzzer!


if __name__ == '__main__':
    from . import test
    test(__name__)
