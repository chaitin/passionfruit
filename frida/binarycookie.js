const NSHTTPCookieStorage = ObjC.classes.NSHTTPCookieStorage;

const store = NSHTTPCookieStorage.sharedHTTPCookieStorage();
const jar = store.cookies();


function str(obj, def) {
  return obj ? obj.toString() : (def || 'N/A');
}

module.exports = function() {
  let cookies = []

  for (let i = 0; i < jar.count(); i++) {
    let cookie = jar.objectAtIndex_(i);
    let item = {
      version: cookie.version().toString(),
      name: cookie.name().toString(),
      value: cookie.value().toString(),
      expiresDate: str(cookie.expiresDate()),
      created: cookie.created().toString(),
      sessionOnly: str(cookie.sessionOnly(), false),
      domain: cookie.domain().toString(),
      partition: str(cookie.partition()),
      path: cookie.path().toString(),
      isSecure: str(cookie.isSecure(), 'false')
    }
    cookies.push(item);
  }

  return cookies;
}