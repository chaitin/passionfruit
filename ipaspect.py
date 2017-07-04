#!/usr/bin/env python3


# import r2pipe


# r2 = r2pipe.open("/bin/ls")
# r2.cmd('aa')
# print(r2.cmd("afl"))
# print(r2.cmdj("aflj"))
#

import zipfile
import os
import shutil
import hashlib
import importlib

import scans


def sha256_checksum(filename, block_size=65536):
    sha256 = hashlib.sha256()
    with open(filename, 'rb') as f:
        for block in iter(lambda: f.read(block_size), b''):
            sha256.update(block)
    return sha256.hexdigest()


class IPAspect(object):

    def __init__(self, path):
        if os.path.isfile(path):
            ver = sha256_checksum(path)
            name = os.path.basename(path)
            root = 'output/%s_%s' % (name, ver)
        elif os.path.isdir(path):
            root = path
        else:
            raise IOError('invalid filename')

        self.ipa_name = path
        self.root = root

    def run(self):
        self.extract()
        for check in scans.checklist:
            plugin = importlib.import_module('scans.%s' % check)
            yield from plugin.scan(self.root)

    def extract(self):
        root = self.root
        if os.path.exists(root):
            return

        os.makedirs(root, exist_ok=True)

        with zipfile.ZipFile(self.ipa_name, 'r') as ipa:
            for info in ipa.infolist():
                decoded = info.filename.encode('CP437').decode('utf8')
                sanitized = os.path.realpath('/%s' % decoded)[1:]
                dest = os.path.join(root, sanitized)
                parent = os.path.dirname(dest)
                if info.is_dir():
                    os.makedirs(dest, exist_ok=True)
                else:
                    if not os.path.isdir(parent):
                        os.makedirs(parent, exist_ok=True)

                    with ipa.open(info.filename) as fin, open(dest, 'wb') as fout:
                        shutil.copyfileobj(fin, fout)


if __name__ == '__main__':
    import sys
    for item in IPAspect(sys.argv[1]).run():
        # todo: template
        print(item['msg'])
