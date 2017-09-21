import { toJSON } from './lib/nsdict'


function info() {
  const mainBundle = ObjC.classes.NSBundle.mainBundle()
  const info = mainBundle.infoDictionary()
  const json = toJSON(info)
  const data = ObjC.classes.NSProcessInfo.processInfo()
    .environment().objectForKey_('HOME') + ''

  const map = {
    name: 'CFBundleDisplayName',
    version: 'CFBundleVersion',
    semVer: 'CFBundleShortVersionString',
    minOS: 'MinimumOSVersion',
  }

  let result = {
    id: mainBundle.bundleIdentifier() + '',
    bundle: mainBundle.bundlePath() + '',
    binary: mainBundle.executablePath() + '',
    data,
    json,
  }

  if (json.hasOwnProperty('CFBundleURLTypes')) {
    result['urls'] = json['CFBundleURLTypes'].map(item => {
      return {
        name: item['CFBundleURLName'],
        schemes: item['CFBundleURLSchemes'],
        role: item['CFBundleTypeRole'],
      }
    })
  }

  for (let key in map) {
    result[key] = json[map[key]] || 'N/A'
  }

  return result
}


function userDefaults() {
  const NSUserDefaults = ObjC.classes.NSUserDefaults
  return NSUserDefaults.alloc().init().dictionaryRepresentation().toString()
}


module.exports = {
  info,
  userDefaults,
}

