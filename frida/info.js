import { toJSON } from './lib/nsdict'

const toString = str => String.prototype.toString.call(str)
const { NSBundle, NSProcessInfo, NSUserDefaults } = ObjC.classes


function info() {
  const mainBundle = NSBundle.mainBundle()
  const json = toJSON(mainBundle.infoDictionary())
  const data = toString(NSProcessInfo.processInfo()
    .environment().objectForKey_('HOME'))

  const map = {
    name: 'CFBundleDisplayName',
    version: 'CFBundleVersion',
    semVer: 'CFBundleShortVersionString',
    minOS: 'MinimumOSVersion',
  }

  const result = {
    id: toString(mainBundle.bundleIdentifier()),
    bundle: toString(mainBundle.bundlePath()),
    binary: toString(mainBundle.executablePath()),
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
  return NSUserDefaults.alloc().init().dictionaryRepresentation().toString()
}


module.exports = {
  info,
  userDefaults,
}

