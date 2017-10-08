import base64ArrayBuffer from '../lib/base64'


const CCOperation = ['kCCEncrypt', 'kCCDecrypt']
const CCAlgorithm = [
  { name: 'kCCAlgorithmAES128', blocksize: 16 },
  { name: 'kCCAlgorithmDES', blocksize: 8 },
  { name: 'kCCAlgorithm3DES', blocksize: 8 },
  { name: 'kCCAlgorithmCAST', blocksize: 8 },
  { name: 'kCCAlgorithmRC4', blocksize: 8 },
  { name: 'kCCAlgorithmRC2', blocksize: 8 },
]

const subject = 'crypto'
const now = () => (new Date()).getTime()

// CCCryptorStatus
// CCCryptorCreate(CCOperation op, CCAlgorithm alg, CCOptions options,
//     const void *key, size_t keyLength, const void *iv,
//     CCCryptorRef *cryptorRef);

Interceptor.attach(Module.findExportByName(null, 'CCCryptorCreate'), {
  onEnter(args) {
    let op = args[0].toInt32()
    let alg = args[1].toInt32()
    let options = args[2].toInt32()
    let key = args[3]
    let keyLength = args[4].toInt32()
    let iv = args[5]

    let strKey = base64ArrayBuffer(Memory.readByteArray(key, keyLength))
    let strIV = iv === 0 ? 'null' : base64ArrayBuffer(Memory.readByteArray(iv, CCAlgorithm[alg].blocksize))

    let time = now()
    let backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE)
      .map(DebugSymbol.fromAddress).filter(e => e.name)

    let operation = CCOperation[op]
    if (operation === 'kCCEncrypt') {
      operation = 'encrypt'
    } else if (operation === 'kCCDecrypt') {
      operation = 'decrypt'
    } else {
      console.error('unknown operation', op)
    }

    send({
      subject,
      func: 'CCCryptorCreate',
      event: operation,
      arguments: {
        algorithm: CCAlgorithm[alg].name,
        key: strKey,
        iv: strIV,
      },
      time,
      backtrace,
    })
  }
})


// CCCryptorStatus
// CCCrypt(CCOperation op, CCAlgorithm alg, CCOptions options,
//     const void *key, size_t keyLength, const void *iv,
//     const void *dataIn, size_t dataInLength, void *dataOut,
//     size_t dataOutAvailable, size_t *dataOutMoved);

Interceptor.attach(Module.findExportByName(null, 'CCCrypt'), {
  onEnter(args) {
    let op = args[0].toInt32()
    let alg = args[1].toInt32()
    let options = args[2].toInt32()
    let key = args[3]
    let keyLength = args[4].toInt32()
    let iv = args[5]
    let dataIn = args[6]
    let dataInLength = args[7].toInt32()
    let dataOut = args[8]
    let dataOutAvailable = args[9]
    let dataOutMoved = args[10]

    this.dataOut = dataOut
    this.dataOutAvailable = dataOutAvailable
    this.dataOutMoved = dataOutMoved

    let strKey = base64ArrayBuffer(Memory.readByteArray(key, keyLength))
    let strIV = iv === 0 ? 'null' : base64ArrayBuffer(Memory.readByteArray(iv, CCAlgorithm[alg].blocksize))

    let strDataIn = base64ArrayBuffer(Memory.readByteArray(dataIn, dataInLength))

    let time = now()
    let backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE)
      .map(DebugSymbol.fromAddress).filter(e => e.name)

    let operation = CCOperation[op]
    if (operation === 'kCCEncrypt') {
      operation = 'encrypt'
    } else if (operation === 'kCCDecrypt') {
      operation = 'decrypt'
    } else {
      console.error('unknown operation', op)
    }

    this.operation = operation
    send({
      subject,
      event: operation,
      arguments: {
        algorithm: CCAlgorithm[alg].name,
        key: strKey,
        iv: strIV,
        in: strDataIn,
      },      
      time,
      backtrace,
    })
  },
  onLeave(retVal) {
    if (retVal.toInt32() !== 0)
      return

    let time = now()
    let { dataOut, dataOutMoved, operation } = this
    let len = Memory.readUInt(dataOutMoved)
    let strDataOut = base64ArrayBuffer(Memory.readByteArray(dataOut, len))

    send({
      subject,
      event: operation,
      arguments: {
        out: strDataOut,
      },
      time,
    })
  }
})