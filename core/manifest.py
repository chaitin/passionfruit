import os
import plistlib


class Manifest(object):
  def __init__(self, filename):
    with open(filename, 'rb') as fp:
      meta = plistlib.load(fp)

    self.dict = meta
    self.app_dir = os.path.dirname(filename)

  # todo: meta programming
  @property
  def executable(self):
    return os.path.join(self.app_dir, self.dict['CFBundleExecutable'])

  @property
  def name(self):
    return self.dict['CFBundleName']

  @property
  def id(self):
    return self.dict['CFBundleIdentifier']

  @property
  def version(self):
    return self.dict['CFBundleShortVersionString']

  @property
  def urls(self):
    url_types = self.dict['CFBundleURLTypes']
    return ['%s://' % url
      for item in url_types 
      for url in item['CFBundleURLSchemes']
      if 'CFBundleURLSchemes' in item]

  def dump(self):
    return plistlib.dumps(self.dict)


def info_plist(directory):
  payload = os.path.join(directory, 'Payload')
  app, = os.listdir(payload)
  if not app.endswith('.app'):
    raise IOError('invalid IPA package %s' % directory)

  return os.path.join(payload, app, 'Info.plist')
  

def load(directory):
  path = info_plist(directory)
  return Manifest(path)

# todo: test code