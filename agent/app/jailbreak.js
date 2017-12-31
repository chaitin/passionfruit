const paths = `/Applications/Cydia.app
/Applications/FakeCarrier.app
/Applications/Icy.app
/Applications/IntelliScreen.app
/Applications/MxTube.app
/Applications/RockApp.app
/Applications/SBSettings.app
/Applications/WinterBoard.app
/Applications/blackra1n.app
/Library/MobileSubstrate/DynamicLibraries/LiveClock.plist
/Library/MobileSubstrate/DynamicLibraries/Veency.plist
/Library/MobileSubstrate/MobileSubstrate.dylib
/System/Library/LaunchDaemons/com.ikey.bbot.plist
/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist
/bin/bash
/bin/sh
/etc/apt
/etc/ssh/sshd_config
/private/var/lib/apt
/private/var/lib/cydia
/private/var/mobile/Library/SBSettings/Themes
/private/var/stash
/private/var/tmp/cydia.log
/usr/bin/sshd
/usr/libexec/sftp-server
/usr/libexec/ssh-keysign
/usr/sbin/sshd
/var/cache/apt
/var/lib/apt
/private/jailbreak.txt
/var/lib/cydia`.split('\n')

const subject = 'jailbreak'

/* eslint no-param-reassign: 0, camelcase: 0, eqeqeq: 0, prefer-destructuring: 0 */
Interceptor.attach(Module.findExportByName(null, 'open'), {
  onEnter(args) {
    if (!args[0])
      return

    const backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE).map(
      DebugSymbol.fromAddress).filter(e => e.name)
    const path = Memory.readUtf8String(args[0])
    if (paths.indexOf(path) > -1) {
      send({
        subject,
        time: new Date().getTime(),
        event: 'detect',
        backtrace,
        arguments: {
          path,
          method: 'open',
        },
        backtrace,
      })
      args[0] = NULL
    }
  },
})

Interceptor.attach(Module.findExportByName(null, 'stat'), {
  onEnter(args) {
    if (!args[0])
      return

    const path = Memory.readUtf8String(args[0])
    const backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE).map(
      DebugSymbol.fromAddress).filter(e => e.name)
    if (paths.indexOf(path) > -1) {
      send({
        subject,
        time: new Date().getTime(),
        event: 'detect',
        backtrace,
        arguments: {
          path,
          method: 'stat',
        },
      })
      args[0] = NULL
    }
  },
})

Interceptor.attach(Module.findExportByName(null, 'getenv'), {
  onEnter(args) {
    const key = Memory.readUtf8String(args[0])
    const backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE).map(
      DebugSymbol.fromAddress).filter(e => e.name)
    if (key === 'DYLD_INSERT_LIBRARIES') {
      send({
        subject,
        time: new Date().getTime(),
        event: 'detect',
        backtrace,
        arguments: {
          env: 'DYLD_INSERT_LIBRARIES',
        },
      })
      args[0] = NULL
    }
  },
})

Interceptor.attach(Module.findExportByName(null, '_dyld_get_image_name'), {
  onLeave(retVal) {
    if (Memory.readUtf8String(retVal).indexOf('MobileSubstrate') > -1)
      retVal.replace(ptr(0x00))
  },
})

Interceptor.attach(Module.findExportByName(null, 'fork'), {
  onLeave(retVal) {
    retVal.replace(ptr(-1))
    // todo: send
  },
})

const { UIApplication, NSURL, NSString, NSError, NSFileManager } = ObjC.classes
const canOpenURL_publicURLsOnly_ = UIApplication['- _canOpenURL:publicURLsOnly:']
Interceptor.attach(canOpenURL_publicURLsOnly_.implementation, {
  onEnter(args) {
    if (args[2] == '0x0')
      return

    const url = ObjC.Object(args[2]).toString()
    const backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE).map(
      DebugSymbol.fromAddress).filter(e => e.name)
    if (/^cydia:\/\//i.exec(url)) {
      args[2] = NSURL.URLWithString_('invalid://')
      this.shouldOverride = true
      send({
        subject,
        time: new Date().getTime(),
        event: 'detect',
        backtrace,
        arguments: {
          url,
        },
      })
    }
  },
  onLeave(retVal) {
    if (this.shouldOverride)
      retVal.replace(ptr('0x00'))
  },
})

Interceptor.attach(NSFileManager['- fileExistsAtPath:'].implementation, {
  onEnter(args) {
    if (args[2] == '0x0')
      return

    const path = new ObjC.Object(args[2]).toString()
    const backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE).map(
      DebugSymbol.fromAddress).filter(e => e.name)
    if (paths.indexOf(path) > -1) {
      send({
        subject,
        time: new Date().getTime(),
        event: 'detect',
        backtrace,
        arguments: {
          path,
        },
      })
      this.shouldOverride = true
    }
  },
  onLeave(retVal) {
    if (this.shouldOverride)
      retVal.replace(ptr('0x00'))
  },
})

Interceptor.attach(NSString['- writeToFile:atomically:encoding:error:'].implementation, {
  onEnter(args) {
    if (args[2] == '0x0')
      return

    const path = ObjC.Object(args[2]).toString()
    const backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE).map(
      DebugSymbol.fromAddress).filter(e => e.name)
    if (path.match(/^\/private/)) {
      send({
        subject,
        time: new Date().getTime(),
        event: 'detect',
        backtrace,
        arguments: {
          path,
        },
      })
      this.shouldOverride = true
      this.error = args[5]
    }
  },
  onLeave() {
    if (this.shouldOverride)
      Memory.writePointer(this.error, NSError.alloc())
  },
})
