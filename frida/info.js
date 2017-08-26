rpc.exports.main = function() {
  const mainBundle = ObjC.classes.NSBundle.mainBundle()
  const info = mainBundle.infoDictionary()

  // todo: CFBundleURLTypes
  // todo: convert infoDictionary to json
  return {
    name: info.objectForKey_('CFBundleDisplayName') + '',
    id: mainBundle.bundleIdentifier() + '',
    version: info.objectForKey_('CFBundleVersion') + '',
    semVer: info.objectForKey_('CFBundleShortVersionString') + '',
    bundle: mainBundle.bundlePath() + '',
    data: ObjC.classes.NSProcessInfo.processInfo().environment().objectForKey_('HOME') + '',
    binary: mainBundle.executablePath() + ''
  }
}