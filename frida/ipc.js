module.exports = function(url) {
  const { LSApplicationWorkspace, NSURL } = ObjC.classes
  let workspace = LSApplicationWorkspace.defaultWorkspace()
  let link = NSURL.URLWithString_(url)
  return workspace.openSensitiveURL_withOptions_(link, NULL)
}