import os

from core.manifest import load as load_meta
import plistlib


# todo: cache meta somewhere
def scan(directory):
  manifest = load_meta(directory)
  urls = manifest.urls
  yield {
    'urls': urls,
    'msg': 'found following urls: \n%s' % '\n'.join(urls)
  }

  yield {
    'raw': plistlib.dumps(manifest.dict),
    'level': 'message',
    'msg': 'content of Info.plist',
  }

  # todo: url fuzzer!


if __name__ == '__main__':
  from . import test
  test(__name__)