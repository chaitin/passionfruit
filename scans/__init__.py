import os


INFO = 0
SECURE = 0
LOW = 1
MIDDLE = 2
CRITICAL = 3


def test(name):
  root = os.path.dirname(__file__)
  testcase = os.path.join(root, '..', 'output',
    'test.ipa_327dcdbd564e48662c31fcb7d4f28617d1dd9cf86ea4acab3cb0342ec7ea8ff3')
  testcase = os.path.realpath(testcase)
  result = __import__(name).scan(testcase)
  print(list(result))


# todo: yield Message from scanners
class Message(object):
  def __init__(self, msg, filename='N/A', level=INFO):
    self.filename = kwargs.get('filename', 'N/A')
    self.level = level
    self.msg = msg

  def __str__(self):
    return str(self.msg)
