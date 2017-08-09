rpc.exports.info = function() {
  const mainBundle = ObjC.classes.NSBundle.mainBundle()
  const info = mainBundle.infoDictionary()

  // todo: CFBundleURLTypes
  return {
    name: info.objectForKey_('CFBundleDisplayName').toString(),
    id: mainBundle.bundleIdentifier().toString(),
    version: info.objectForKey_('CFBundleVersion').toString(),
    semVer: info.objectForKey_('CFBundleShortVersionString').toString(),
    bundle: mainBundle.bundlePath().toString(),
    data: ObjC.classes.NSProcessInfo.processInfo().environment().objectForKey_('HOME').toString(),
    binary: mainBundle.executablePath().toString()
  }
}