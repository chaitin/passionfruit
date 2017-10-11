const STATUS_OK = 0

module.exports = () => {
  const addr = Module.findExportByName('passionfruit.dylib', 'passionfruit_checkport');
  const lsof = new NativeFunction(addr, 'int', ['pointer', 'pointer']);
  const len = 2048;

  const pSize = Memory.alloc(Process.pointerSize)
  const pBuf = Memory.alloc(len)

  Memory.writePointer(pSize, ptr(len));

  if (lsof(pBuf, pSize) !== STATUS_OK)
    throw new Error('lsof plugin returns non zero status, check console for detail')

  return Memory.readUtf8String(pBuf); // deserialize later
}
