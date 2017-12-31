import base64ArrayBuffer from './lib/base64'


const { UIWindow, NSThread } = ObjC.classes

const CGFloat = (Process.pointerSize === 4) ? 'float' : 'double'
const CGSize = [CGFloat, CGFloat]

const UIGraphicsBeginImageContextWithOptions = new NativeFunction(
  Module.findExportByName('UIKit', 'UIGraphicsBeginImageContextWithOptions'),
  'void', [CGSize, 'bool', CGFloat])

const UIGraphicsEndImageContext = new NativeFunction(
  Module.findExportByName('UIKit', 'UIGraphicsEndImageContext'),
  'void', [])

const UIGraphicsGetImageFromCurrentImageContext = new NativeFunction(
  Module.findExportByName('UIKit', 'UIGraphicsGetImageFromCurrentImageContext'),
  'pointer', [])

const UIImagePNGRepresentation = new NativeFunction(
  Module.findExportByName('UIKit', 'UIImagePNGRepresentation'),
  'pointer', ['pointer'])

function performOnMainThread(action) {
  return new Promise((resolve, reject) => {
    function performAction() {
      try {
        const result = action()
        resolve(result)
      } catch (e) {
        reject(e)
      }
    }

    if (NSThread.isMainThread())
      performAction()
    else
      ObjC.schedule(ObjC.mainQueue, performAction)
  })
}

export default function screenshot() {
  return performOnMainThread(() => {
    const view = UIWindow.keyWindow()
    const bounds = view.bounds()
    const size = bounds[1]
    UIGraphicsBeginImageContextWithOptions(size, 0, 0)
    view.drawViewHierarchyInRect_afterScreenUpdates_(bounds, true)

    const image = UIGraphicsGetImageFromCurrentImageContext()
    UIGraphicsEndImageContext()

    const png = new ObjC.Object(UIImagePNGRepresentation(image))
    const buffer = Memory.readByteArray(png.bytes(), png.length())

    return base64ArrayBuffer(buffer)
  })
}
