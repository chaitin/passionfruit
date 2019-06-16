const { NSThread, UIScreen, UIApplication } = ObjC.classes

const CGFloat = (Process.pointerSize === 4) ? 'float' : 'double'
const CGSize = [CGFloat, CGFloat]

const UIGraphicsBeginImageContextWithOptions = new NativeFunction(
  Module.findExportByName('UIKit', 'UIGraphicsBeginImageContextWithOptions'),
  'void', [CGSize, 'bool', CGFloat],
)

const UIGraphicsEndImageContext = new NativeFunction(
  Module.findExportByName('UIKit', 'UIGraphicsEndImageContext'),
  'void', [],
)

const UIGraphicsGetImageFromCurrentImageContext = new NativeFunction(
  Module.findExportByName('UIKit', 'UIGraphicsGetImageFromCurrentImageContext'),
  'pointer', [],
)

const UIImagePNGRepresentation = new NativeFunction(
  Module.findExportByName('UIKit', 'UIImagePNGRepresentation'),
  'pointer', ['pointer'],
)

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
    const bounds = UIScreen.mainScreen().bounds()
    const cgsize = bounds[1]
    const statusbar = UIApplication.sharedApplication().valueForKey_('statusBarWindow').valueForKey_('statusBar')
    UIGraphicsBeginImageContextWithOptions(cgsize, 0, 0)
    const windows = UIApplication.sharedApplication().windows()
    for (let index = 0; index < windows.count(); index++) {
      const currentwindow = windows.objectAtIndex_(index)
      currentwindow.drawViewHierarchyInRect_afterScreenUpdates_(currentwindow.bounds(), true)
    }

    statusbar.drawViewHierarchyInRect_afterScreenUpdates_(statusbar.bounds(), true)
    const image = UIGraphicsGetImageFromCurrentImageContext()
    UIGraphicsEndImageContext()

    const png = new ObjC.Object(UIImagePNGRepresentation(image))
    console.log(png.base64EncodedStringWithOptions_(0))
    return png.base64EncodedStringWithOptions_(0).toString()
  })
}
