function ReadOnlyMemoryBuffer(address, size) {
  this.base = address
  this.length = size || 4096
}

const mapping = [
  ['Int', 'Int', 4],
  ['UInt', 'UInt', 4],
  ['Float', 'Float', 4],
  ['Double', 'Double', 8],
  ['Int8', 'S8', 1],
  ['UInt8', 'U8', 1],
  ['Int16', 'S16', 2],
  ['UInt16', 'U16', 2],
  ['Int32', 'S32', 4],
  ['UInt32', 'U32', 4],
]

const isLE = ((new Uint32Array((new Uint8Array([1, 2, 3, 4])).buffer))[0] === 0x04030201)
const proto = ReadOnlyMemoryBuffer.prototype

proto.slice = function(begin, end) {
  const size = (typeof end === 'undefined' ? this.length : end ) - begin
  return new ReadOnlyMemoryBuffer(this.base.add(begin), size)
}

proto.toString = function() {
  return Memory.readUtf8String(this.base)
}

const stub = () => {
  throw new Error('not implemented')
}

mapping.forEach((type) => {
  const [bufferType, fridaType, size] = type

  proto['read' + bufferType] = function(offset) {
    const address = this.base.add(offset)
    return Memory['read' + fridaType](address)
  }

  proto['write' + bufferType] = stub

  if (size > 1) {
    // le, be
    proto['read' + bufferType + 'LE'] = isLE ? proto['read' + bufferType] : stub
    proto['read' + bufferType + 'BE'] = isLE ? stub : proto['read' + bufferType]

    // readonly
    proto['write' + bufferType + 'LE'] = proto['write' + bufferType + 'BE'] = stub
  }
})

export default ReadOnlyMemoryBuffer
