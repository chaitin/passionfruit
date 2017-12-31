import { arrayFromNSArray } from './app/lib/nsdict'

const {
  SBBacklightController,
  SBLockScreenManager,
  SBApplicationController,
  SBUIController,
  
  LSApplicationWorkspace,
  NSURL,
} = ObjC.classes

const perform = f => ObjC.schedule(ObjC.mainQueue, f)
const workspace = LSApplicationWorkspace.defaultWorkspace()

rpc.exports = {
  unlock() {
    perform(() => {
      SBBacklightController.sharedInstance().turnOnScreenFullyWithBacklightSource_(0)
      SBLockScreenManager.sharedInstance().unlockUIFromSource_withOptions_(0, null)
    })
  },

  uiopen(url) {
    const link = NSURL.URLWithString_(url)
    return workspace.openSensitiveURL_withOptions_(link, NULL)
  },

  urls() {
    return {
      'public': arrayFromNSArray(workspace.publicURLSchemes()),
      'private': arrayFromNSArray(workspace.privateURLSchemes()),
    }
  },

  activate(bundle) {
    perform(() => {
      const controller = SBApplicationController.sharedInstance()
      const app = typeof controller.applicationWithBundleIdentifier_ === 'function' ?
        controller.applicationWithBundleIdentifier_(bundle) : // iOS 8+
        controller.applicationWithDisplayIdentifier_(bundle) // iOS 7-
      SBUIController.sharedInstanceIfExists().activateApplication_(app)
    })
  },
}
