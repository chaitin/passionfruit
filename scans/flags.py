import subprocess
import os
import plistlib

from core.manifest import load as load_meta


def check_pie(filename):
  output = subprocess.check_output(['otool', '-hv', filename])
  if b'PIE' in output:
    yield {
      'level': 'SECURE',
      'filename': filename,
      'msg': 'fPIE -pie is found',
    }


def check_sp_and_arc(filename):
  output = subprocess.check_output(['otool', '-Iv', filename])
  # print(output.decode())
  # todo: disassembly and CFG
  if b'stack_chk_guard' in output:
    yield {
      'level': 'SECURE',
      'filename': filename,
      'msg': 'fstack-protector-all is found.',
    }
  else:
    yield {
      'level': 'HIGH',
      'filename': filename,
      'msg': 'fstack-protector-all not found, app is vulnerable to Stack Overflows/Stack Smashing Attacks.',
    }

  if b'_objc_release' in output:
    yield {
      'level': 'SECURE',
      'filename': filename,
      'msg': 'fobjc-arc is found.'
    }
  else:
    yield {
      'level': 'HIGH',
      'filename': filename,
      'msg': 'fobjc-arc not found.'
    }


def scan(directory):
  meta = load_meta(directory)
  macho = meta.executable

  yield from check_pie(macho)
  yield from check_sp_and_arc(macho)


if __name__ == '__main__':
  from . import test
  test(__name__)
