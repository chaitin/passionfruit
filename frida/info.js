const NSDictUtil = require('./NSDictUtil')


module.exports = function() {
  const mainBundle = ObjC.classes.NSBundle.mainBundle()
  const info = mainBundle.infoDictionary()
  const json = NSDictUtil.toJSON(info)
  const data = ObjC.classes.NSProcessInfo.processInfo()
    .environment().objectForKey_('HOME') + ''

  const map = {
    name: 'CFBundleDisplayName',
    version: 'CFBundleVersion',
    semVer: 'CFBundleShortVersionString',
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
    result[key] = json[key] || 'N/A'
  }

  return result
}