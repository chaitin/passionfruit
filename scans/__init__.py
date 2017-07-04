import os
import importlib


INFO = 0
SECURE = 0
LOW = 1
MEDIUM = 2
CRITICAL = 3


def test(name):
    root = os.path.dirname(__file__)
    testcase = os.path.join(
        root, '..', 'output',
        'DVIA.ipa_1934a73c32df86ccb6887bd19' +
        '8536dfc7e674c2c16a79e94724c3ee2be437ac5')
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


checklist = ['flags', 'infoleak', 'metainfo']

__all__ = ['INFO', 'SECURE', 'LOW', 'MEDIUM', 'CRITICAL'] + checklist
