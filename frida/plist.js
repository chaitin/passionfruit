import { toJSON } from './lib/nsdict'


function load(path) {
  let info = ObjC.classes.NSDictionary.dictionaryWithContentsOfFile_(path)
  return toJSON(info)
}


module.exports = load