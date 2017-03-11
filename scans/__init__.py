import os

from . import flags, infoleak, metainfo


def test(name):
  root = os.path.dirname(__file__)
  testcase = os.path.join(root, '..', 'output',
    'test.ipa_327dcdbd564e48662c31fcb7d4f28617d1dd9cf86ea4acab3cb0342ec7ea8ff3')
  testcase = os.path.realpath(testcase)
  result = __import__(name).scan(testcase)
  print(list(result))

