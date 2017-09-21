const STATUS_OK = 0

module.exports = function() {
  const addr = Module.findExportByName('ipaspect.dylib', 'ipaspect_checkport');
  const lsof = new NativeFunction(addr, 'int', ['pointer', 'pointer']);
  const len = 2048;

  let pSize = Memory.alloc(Process.pointerSize)
  let pBuf = Memory.alloc(len)

  Memory.writePointer(pSize, ptr(len));

  if (lsof(pBuf, pSize) != STATUS_OK) {
    throw new Error('lsof plugin returns non zero status, check console for detail')
  }

  return Memory.readUtf8String(pBuf); // deserialize later
}