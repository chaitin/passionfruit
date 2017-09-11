const NSUserDefaults = ObjC.classes.NSUserDefaults;

exports.toString = function() {
  return NSUserDefaults.alloc().init().dictionaryRepresentation().toString();
}

// todo: get by key
// todo: convery NSDictionary to js object