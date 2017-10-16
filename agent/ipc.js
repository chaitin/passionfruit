// fixme: this private api only works in SpringBoard

module.exports = (url) => {
  const { LSApplicationWorkspace, NSURL } = ObjC.classes
  const workspace = LSApplicationWorkspace.defaultWorkspace()
  const link = NSURL.URLWithString_(url)
  return workspace.openSensitiveURL_withOptions_(link, NULL)
}
