'use strict';

const fatmacho = require('fatmacho');
const macho = require('macho');
import ReadOnlyMemoryBuffer from './lib/romembuffer'
//const fs = require('fs');

const cpuArch = (Process.pointerSize === 4) ? '32' : '64'

const CSSLOT_CODEDIRECTORY = 0;
const CSSLOT_REQUIREMENTS = 2;
const CSSLOT_ENTITLEMENTS = 5;

function turnToBigEndian(value){
  var bytes = new Uint8Array(4);
  var bigendian = ''
  bytes[3] = value >> (24) & 255; 
  bytes[2] = value >> (16) & 255; 
  bytes[1] = value >> (8) & 255; 
  bytes[0] = value >> (0) & 255;
  for (var i = 0; i < bytes.length ; i ++) {
     bigendian = bigendian.concat(bytes[i].toString(16))
  }
  return parseInt(bigendian, 16)
}

/*function parseEntitlements (data) {
  //turn to big endian
   return data
  const count = turnToBigEndian(Memory.readU32(data.base+8));

  for (let i = 0; i < count; i++) {
    const base = 8 * i;
    const type = turnToBigEndian(Memory.readU32(data.base+base + 12));
    const blob = turnToBigEndian(Memory.readU32(data.base+base + 16));
    if (type === CSSLOT_ENTITLEMENTS) {
      const size = turnToBigEndian(Memory.readU32(data.base+blob + 4));
      return data.slice(blob + 8, blob + size);
    }
  }
  return null;
}*/

function parseEntitlements(data) {
  const count = data.readUInt32BE(8)
  for (var i = 0; i < count; i++) {
    const base = 8 * i
    const type = data.readUInt32BE(base + 12)
    const blob = data.readUInt32BE(base + 16)
    if (type === CSSLOT_ENTITLEMENTS) {
      const size = data.readUInt32BE(blob + 4)
      const buf = data.slice(blob + 8, blob + size)
      return Memory.readUtf8String(buf.base, buf.length)
    }
  }
  return null;
}

function getEntitlements (data, machoObject) {
  for (let cmd of machoObject.cmds) {
    if (cmd.type === 'code_signature') {
      //return cmd.datasize
      return parseEntitlements(data.slice(cmd.dataoff));
    }
  }
  //return test;
}

function getEntitlementsFromBuffer (data) {
  try {
    const hdrs = macho.parse(data);
    return getEntitlements(data, hdrs);
  } catch (e) {
    try {
      const bins = fatmacho.parse(data);
      const hdrs = macho.parse(bins[0].data);
      return getEntitlements(bins[0].data, hdrs);
    } catch (e2) {
      return '{error:error}';
    }
  }
}

/*function getEntitlementsFromMemory () {
  const [appModule, ] = Process.enumerateModulesSync()
  const data = new ReadOnlyMemoryBuffer(appModule.base, appModule.size)
  return getEntitlementsFromBuffer(data);
}*/

const { NSPipe, NSFileHandle, NSTask, NSData, NSString, NSArray} = ObjC.classes

/*
NSPipe *pipe = [NSPipe pipe];
NSFileHandle *file = pipe.fileHandleForReading;

NSTask *task = [[NSTask alloc] init];
task.launchPath = @"/usr/bin/grep";
task.arguments = @[@"foo", @"bar.txt"];
task.standardOutput = pipe;

[task launch];

NSData *data = [file readDataToEndOfFile];
[file closeFile];

NSString *grepOutput = [[NSString alloc] initWithData: data encoding: NSUTF8StringEncoding];
NSLog (@"grep returned:\n%@", grepOutput);
*/

function getEntitlementsFromCommand(path){
  const pipe = NSPipe.pipe()
  const file = pipe.fileHandleForReading()
  const task = NSTask.alloc().init()
  const launchpath = "/usr/bin/ldid"
  task.setLaunchPath_(NSString.stringWithString_(launchpath))
  task.setArguments_(NSArray.arrayWithObjects_(NSString.stringWithString_("-e"), path))
  task.setStandardOutput_(pipe)
  task.launch()
  const data = file.readDataToEndOfFile()
  return NSString.alloc().initWithData_encoding_(data,4).toString()
}



module.exports = {
  getEntitlementsFromMemory,
  getEntitlementsFromCommand,
}