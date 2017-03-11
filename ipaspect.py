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

import scans
import scans.flags
import scans.infoleak
import scans.metainfo


def sha256_checksum(filename, block_size=65536):
    sha256 = hashlib.sha256()
    with open(filename, 'rb') as f:
        for block in iter(lambda: f.read(block_size), b''):
            sha256.update(block)
    return sha256.hexdigest()


class IPAspect(object):
  def __init__(self, ipa_name):
    ver = sha256_checksum(ipa_name)
    name = os.path.basename(ipa_name)
    root = 'output/%s_%s' % (name, ver)

    self.ipa_name = ipa_name
    self.root = root


  def run(self):
    self.extract()

    # todo: configurable checklist?
    for name in ['flags', 'infoleak', 'metainfo']:
      yield from getattr(scans, name).scan(self.root)


  def extract(self):
    root = self.root
    if os.path.exists(root):
      return

    os.makedirs(root, exist_ok=True)

    with zipfile.ZipFile(self.ipa_name, 'r') as ipa:
      for arcname in ipa.namelist():
        # fix encoding issue
        src = arcname.encode('CP437').decode('utf8')
        secure_path = os.path.realpath('/%s' % src)[1:]

        dest = os.path.join(root, secure_path)
        parent = os.path.dirname(dest)
        if not os.path.exists(parent):
          os.makedirs(parent, exist_ok=True)

        with ipa.open(arcname) as fin, open(dest, 'wb') as fout:
          shutil.copyfileobj(fin, fout)


if __name__ == '__main__':
  for item in IPAspect('data/test.ipa').run():
    print(item['msg'])

