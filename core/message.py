
class Message(object):
  def __init__(self, msg, level='INFO', filename='N/A', issue='', extra=None):
    self.msg = msg
    self.level = level
    self.filename = filename
    self.issue = issue
    self.extra = extra

  def __str__(self):
    return '[%s] %s' % (self.level, self.msg)