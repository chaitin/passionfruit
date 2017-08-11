import subprocess
import os
import plistlib

from core.manifest import load as load_meta
from core.message import Message


# todo: lief

def check_pie(filename):
    output = subprocess.check_output(['otool', '-hv', filename])
    if b'PIE' in output:
        yield Message('fPIE -pie is found', filename=filename)


def check_restrict(filename):
    output = subprocess.check_output(['otool', '-l', filename])
    if b'sectname __restrict' in output and b'segname __RESTRICT' in output:
        yield Message('__restrict section is found', filename=filename)


def check_sp_and_arc(filename):
    output = subprocess.check_output(['otool', '-Iv', filename])
    # print(output.decode())
    # todo: disassembly and CFG
    if b'stack_chk_guard' in output:
        yield Message('fstack-protector-all has been found', filename=filename)
    else:
        yield Messsage(
            'fstack-protector-all not found, app ' +
            'is vulnerable to Stack Overflows/Stack Smashing Attacks.',
            level='CRITICAL',
            filename=filename)

    if b'_objc_release' in output:
        yield Message('fobjc-arc has been found', filename=filename)
    else:
        yield Message(
            'fobjc-arc has not been enabled. Use ARC for better memory management.',
            level='MEDIUM',
            filename=filename)


def scan(directory):
    meta = load_meta(directory)
    macho = meta.executable

    yield from check_pie(macho)
    yield from check_sp_and_arc(macho)
    yield from check_restrict(macho)


if __name__ == '__main__':
    from . import test
    test(__name__)
