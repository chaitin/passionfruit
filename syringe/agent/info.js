rpc.exports.info = function() {
  const info = ObjC.classes.NSBundle.mainBundle().infoDictionary()

  return {
    name: info.objectForKey_('CFBundleName').toString(),
    id: ObjC.classes.NSBundle.mainBundle().bundleIdentifier().toString(),
    version: info.objectForKey_('CFBundleVersion').toString(),
    bundle: ObjC.classes.NSBundle.mainBundle().bundlePath().toString(),
    data: ObjC.classes.NSProcessInfo.processInfo().environment().objectForKey_('HOME').toString(),
    binary: ObjC.classes.NSBundle.mainBundle().executablePath().toString(),
  }
}