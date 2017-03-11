import os

from core.manifest import load as load_meta


# todo: cache meta somewhere
def scan(directory):
  urls = load_meta(directory).urls
  yield {
    'urls': urls,
    'msg': 'found following urls: \n%s' % '\n'.join(urls)
  }

  # todo: url fuzzer!


if __name__ == '__main__':
  from . import test
  test(__name__)