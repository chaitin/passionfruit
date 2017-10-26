import { toJSON } from './lib/nsdict'
import { NSTemporaryDirectory } from './lib/foundation'

const { NSBundle, NSProcessInfo, NSUserDefaults } = ObjC.classes


function info() {
  const mainBundle = NSBundle.mainBundle()
  const json = toJSON(mainBundle.infoDictionary())
  const data = NSProcessInfo.processInfo()
    .environment().objectForKey_('HOME').toString()
  const tmp = new ObjC.Object(NSTemporaryDirectory())

  const map = {
    name: 'CFBundleDisplayName',
    version: 'CFBundleVersion',
    semVer: 'CFBundleShortVersionString',
    minOS: 'MinimumOSVersion',
  }

  const result = {
    id: mainBundle.bundleIdentifier().toString(),
    bundle: mainBundle.bundlePath().toString(),
    binary: mainBundle.executablePath().toString(),
    tmp,
    data,
    json,
  }

  /* eslint dot-notation: 0 */
  if (Object.prototype.hasOwnProperty.call(json, 'CFBundleURLTypes'))
    result.urls = json['CFBundleURLTypes'].map(item => ({
      name: item['CFBundleURLName'],
      schemes: item['CFBundleURLSchemes'],
      role: item['CFBundleTypeRole'],
    }))

  /* eslint guard-for-in: 0 */
  for (const key in map)
    result[key] = json[map[key]] || 'N/A'

  return result
}


function userDefaults() {
  return toJSON(NSUserDefaults.alloc().init().dictionaryRepresentation())
}


module.exports = {
  info,
  userDefaults,
}

