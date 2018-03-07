'use strict';

const fatmacho = require('fatmacho');
const macho = require('macho');
import ReadOnlyMemoryBuffer from './lib/romembuffer'
//const fs = require('fs');

const CSSLOT_CODEDIRECTORY = 0;
const CSSLOT_REQUIREMENTS = 2;
const CSSLOT_ENTITLEMENTS = 5;

function parseEntitlements (data) {
  const count = Memory.readU32(data+8);
  for (let i = 0; i < count; i++) {
    const base = 8 * i;
    const type = Memory.readU32(data+base + 12);
    const blob = Memory.readU32(data+base + 16);
    if (type === CSSLOT_ENTITLEMENTS) {
      const size = Memory.readU32(data+blob + 4);
      return data.slice(blob + 8, blob + size);
    }
  }
  return null;
}

function getEntitlements (data, machoObject) {
  for (let cmd of machoObject.cmds) {
    if (cmd.type === 'code_signature') {
      return parseEntitlements(data.slice(cmd.dataoff));
    }
  }
  return null;
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
      return null;
    }
  }
}

function getEntitlementsFromMemory () {
  const [appModule, ] = Process.enumerateModulesSync()
  const data = new ReadOnlyMemoryBuffer(appModule.base, appModule.size)
  return getEntitlementsFromBuffer(data);
}

module.exports = {
  getEntitlementsFromMemory,
}