# Passionfruit

[![npm version](https://badge.fury.io/js/passionfruit.svg)](https://badge.fury.io/js/passionfruit)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Simple iOS app blackbox assessment tool. Powered by [frida.re](https://www.frida.re) and [vuejs](https://www.vuejs.org).

## Features

* **Cross plarform web GUI!**
* Also supports non-jailbroken device (see [Non-jailbroken device](#non-jailbroken-device)).
* List all url schemes.
* List human readable app meta info (Info.plist).
* Capture screenshot.
* Checksec: see if target app is encrypted, and has enabled PIE, ARC and stack canary.
* App sandbox file browser. Directly preview images, SQLite databases and plist files on device. You can always download the file for further investigation.
* Check the loaded frameworks. Hook exported native functions from these dylib to print the arguments and stack trace.
* Log SQLite operations.
* Log and try to bypass jailbreak detection.
* List Objective-C classes from app, hook the methods and inspect the arguments and stack trace.
* Read keychain items.
* Read cookies.
* Read UserDefaults.
* Simple ui dump.

## Screenshots

![General](screenshot/metainfo.png)

Checksec, url schemes and metainfo.

![Finder](screenshot/finder.png)

File browser with hex viewer, image viewer, plist viewer and SQLite database reader.

![Modules](screenshot/modules.png)

Loaded frameworks and their exported symbols.

![Classes](screenshot/classes.png)

![Methods](screenshot/methods.png)

Objective C classes and methods.

![Console](screenshot/console.png)

Intercepted calls, arguments and stack trace.

![UIDump](screenshot/uidump.png)

Dump ui description of the key window.

![keychain](screenshot/keychain.png)

KeyChain reader.

## Setup

### Desktop requirements:

* Latest [node.js](https://nodejs.org/) (>=7.10.1) and [npm](https://www.npmjs.com) to run the api server and web gui
* Any modern desktop browser you like

Passionfruit is now avaliable on npm, so just type following command to install:

```shell
npm install -g passionfruit
```

Then launch it:

```shell
passionfruit
```

Note that if the port 31337 is in use, set environment variable `PORT` to use an alternative port. Also, setting `HOST` can force to listen on an alternative interface, but be careful because it has no authentication yet: 

```
HOST=192.168.1.100 PORT=12345 passionfruit
```

### Device setup:

#### Jailbroken Device

See https://www.frida.re/docs/ios/

> Start `Cydia` and add Frida’s repository by going to `Manage` -> `Sources` -> `Edit` -> `Add` and enter `https://build.frida.re`. You should now be able to find and install the `Frida` package which lets Frida inject JavaScript into apps running on your iOS device. This happens over USB, so you will need to have your USB cable handy, though there’s no need to plug it in just yet.

#### Non-jailbroken Device

Official documentation of frida.re (linked above) also introduces how to inject [FridaGadget.dylib](https://build.frida.re/frida/ios/lib/FridaGadget.dylib) to the ipa, requires repack and resign.

Here are some articles about how to do so:

* [MonkeyDev/wiki/非越狱App集成#集成frida](https://github.com/AloneMonkey/MonkeyDev/wiki/%E9%9D%9E%E8%B6%8A%E7%8B%B1App%E9%9B%86%E6%88%90#集成frida)（Chinese)
* https://github.com/tanprathan/Fridpa
* https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2016/october/ios-instrumentation-without-jailbreak/

## Development setup

Clone this project and install requirements:

```shell
git clone https://github.com/chaitin/passionfruit.git
npm install
cd gui
npm install
```

For those who wants to contribute, you may probably need to restart the api server and reload webpage each time you make a change. The following steps enable livereload.

#### API server

```shell
yarn
npm run dev
```

#### Webpack server

```shell
cd gui
yarn
npm run dev
```

#### Frida script compiler

Frida agent needs to be compiled at the first time: `npm run build`

If you need livereload like webpack, use `npm run watch`.

Now open `http://localhost:8080` in browser.

## FAQ

### Why node.js is complaining about syntax error?

This project uses the lastest ECMAScript feature in server side. You need nodejs v7.10.1 at least, but v8.x and above is recommended. I've got some users reporting that yarn is not compatible with lower nodejs version.

### "Device is not an iOS device, or you have not installed frida on it"

Make sure you have frida.re successfully installed. Also, check if the version on of frida on device matches. Frida offers both 32bit and 64bit version, wrong architecture will not work. 

### Have problem with `npm install/build`?

Users from China mainland may encounter network problem. Try npm mirrors like [cnpm](https://npm.taobao.org/).

All npm command mentioned above can be replaced with [yarn](https://yarnpkg.com/), if you prefer.

Besides, after updating source with `git pull`, or having nodejs engine upgraded, you may need to remove `node_modules` directory and re-run `npm install ; npm run build`.

## LICENCE

MIT
