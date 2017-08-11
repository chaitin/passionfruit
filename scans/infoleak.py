import subprocess
import os
import glob
import re
import plistlib


from core.message import Message


# 10.0.0.0-10.255.255.255
# 172.16.0.0—172.31.255.255
# 192.168.0.0-192.168.255.255

__RE_INTERNAL_IP__ = \
    '((192\.168|172\.([1][6-9]|[2]\d|3[01]))' + \
    '(\.([2][0-4]\d|[2][5][0-5]|[01]?\d?\d)){2}|' + \
    '10(\.([2][0-4]\d|[2][5][0-5]|[01]?\d?\d)){3})'


def deep_values(obj):
    if type(obj) is dict:
        for val in obj.values():
            yield from deep_values(val)
    elif type(obj) in (list, tuple):
        for val in obj:
            yield from deep_values(val)
    else:
        yield obj


def check_plist(directory):
    pattern = os.path.join(directory, '**/*.plist')
    for filename in glob.glob(pattern, recursive=True):
        with open(filename, 'rb') as fp:
            try:
                root = plistlib.load(fp)
            except:
                continue

            for val in deep_values(root):
                if type(val) is str and re.search(__RE_INTERNAL_IP__, val):
                    yield Message(
                        'found [%s]' % val,
                        filename=filename,
                        level='MEDIUM'
                        issue='Internal IP (may be false positive)')


def check_string(directory):
    try:
        output = subprocess.check_output(
            ['egrep', '-r', __RE_INTERNAL_IP__, directory])
    except:
        yield Message('No internal IP found in plain text files',
                      issue='Internal IP (may be false positive)')

        return

    for line in output.decode('utf8').split('\n'):
        try:
            filename, body = line.split(':', 1)
        except:
            filename = line[len('Binary file '):-len(' matches')]
            body = 'binary matches'

        yield Message(
            'found [%s]' % body,
            filename=filename,
            level='MEDIUM'
            issue='Internal IP (may be false positive)')


def scan(directory):
    yield from check_string(directory)
    yield from check_plist(directory)


if __name__ == '__main__':
    from . import test
    test(__name__)
