const { NSHTTPCookieStorage } = ObjC.classes

const store = NSHTTPCookieStorage.sharedHTTPCookieStorage()
const jar = store.cookies()

function str(obj, def) {
  return obj ? obj.toString() : (def || 'N/A')
}

module.exports = function binaryCookies() {
  const cookies = []

  for (let i = 0; i < jar.count(); i++) {
    const cookie = jar.objectAtIndex_(i)
    const item = {
      version: cookie.version().toString(),
      name: cookie.name().toString(),
      value: cookie.value().toString(),
      domain: cookie.domain().toString(),
      path: cookie.path().toString(),
      isSecure: str(cookie.isSecure(), 'false'),
    }
    cookies.push(item)
  }

  return cookies
}
