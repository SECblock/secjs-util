
const secp256k1 = require('secp256k1')
const createKeccakHash = require('keccak')
const createHash = require('create-hash')
const isHexPrefixed = require('is-hex-prefixed')
const stripHexPrefix = require('strip-hex-prefix')
const assert = require('assert')
const Buffer = require('safe-buffer').Buffer
const rlp = require('rlp')
const BN = require('bn.js')
const crypto = require('crypto')
const EC = require('elliptic').ec
const RIPEMD160 = require('ripemd160')
const bs58 = require('bs58')
const dgram = require('dgram')
const fs = require('fs')
const bip39 = require('bip39')
const ec = new EC('secp256k1')

const ntpPort = '123'
const ADDRESS_VERSION = 1
const FILE_PATH = process.cwd() + 'timeDiff.txt'

/**
 * the max integer that this VM can handle (a ```BN```)
 * @var {BN} MAX_INTEGER
 */
exports.MAX_INTEGER = new BN('ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff', 16)

/**
 * 2^256 (a ```BN```)
 * @var {BN} TWO_POW256
 */
exports.TWO_POW256 = new BN('10000000000000000000000000000000000000000000000000000000000000000', 16)

/**
 * Keccak-256 hash of null (a ```String```)
 * @var {String} KECCAK256_NULL_S
 */
exports.KECCAK256_NULL_S = 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470'

/**
 * Keccak-256 hash of null (a ```Buffer```)
 * @var {Buffer} KECCAK256_NULL
 */
exports.KECCAK256_NULL = Buffer.from(exports.KECCAK256_NULL_S, 'hex')

/**
 * Keccak-256 of an RLP of an empty array (a ```String```)
 * @var {String} KECCAK256_RLP_ARRAY_S
 */
exports.KECCAK256_RLP_ARRAY_S = '1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347'

/**
 * Keccak-256 of an RLP of an empty array (a ```Buffer```)
 * @var {Buffer} KECCAK256_RLP_ARRAY
 */
exports.KECCAK256_RLP_ARRAY = Buffer.from(exports.KECCAK256_RLP_ARRAY_S, 'hex')

/**
 * Keccak-256 hash of the RLP of null  (a ```String```)
 * @var {String} KECCAK256_RLP_S
 */
exports.KECCAK256_RLP_S = '56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421'

/**
 * Keccak-256 hash of the RLP of null (a ```Buffer```)
 * @var {Buffer} KECCAK256_RLP
 */
exports.KECCAK256_RLP = Buffer.from(exports.KECCAK256_RLP_S, 'hex')

/**
 * [`BN`](https://github.com/indutny/bn.js)
 * @var {Function}
 */
exports.BN = BN

/**
 * [`rlp`](https://github.com/SEC-block/secjs-rlp)
 * @var {Function}
 */
exports.rlp = rlp

/**
 * [`secp256k1`](https://github.com/cryptocoinjs/secp256k1-node/)
 * @var {Object}
 */
exports.secp256k1 = secp256k1

// -------------------------------------------------------------------------------------------------- //
// ------------------------------------  Time related functions  ------------------------------------ //
// -------------------------------------------------------------------------------------------------- //

exports.currentUnixTimeInMillisecond = function () {
  let CurrentUnixtime = 0
  try {
    let date = new Date()
    CurrentUnixtime = date.getTime()
  } catch (e) {
    console.log('ERROR：' + e)
  }
  return CurrentUnixtime
}

/**
 * @param  {} anyUnixtime = unix time in number
 * @param  {} datetime=convert to date time
 */
exports.getDatetime = function (anyUnixtime) {
  let date = new Date(anyUnixtime)
  let Y = date.getFullYear() + '-'
  let M = (date.getMonth() + 1 < 10 ? '0' + (date.getMonth() + 1) : date.getMonth() + 1) + '-'
  let D = date.getDate() + ' '
  let h = date.getHours() + ':'
  let m = date.getMinutes() + ':'
  let s = date.getSeconds()
  let datetime = Y + M + D + h + m + s
  return datetime
}

exports.currentUnixTimeSecond = function () {
  let currentUnixTimeInSecond = Math.round(exports.currentUnixTimeInMillisecond() / 1000)
  return currentUnixTimeInSecond
}

/**
 * @param  {} anyDate= date time in String,'YYYY MM DD HH:MM:SS:MS'
 * @param  {} unixtime=convert to unix time
 */
exports.getUnixtime = function (anyDate) {
  let date = new Date(anyDate.replace(/-/g, '/'))
  let unixtime = date.getTime()
  return unixtime
}

/**
//  * get unix time from time server
//  * @return {Promise}
//  */
exports.asyncGetUTCTimeFromServer = function (ntpTimeServerAddress) {
  return new Promise((resolve, reject) => {
    let ntpClient = dgram.createSocket('udp4')
    let ntpData = Buffer.alloc(48)
    ntpData[0] = 0x1B
    ntpClient.on('error', (err) => {
      if (err) {
        ntpClient.close()
        reject(err)
      }
    })

    ntpClient.send(ntpData, ntpPort, ntpTimeServerAddress, (err) => {
      if (err) {
        ntpClient.close()
        reject(err)
      }
    })

    ntpClient.once('message', (msg) => {
      let offsetTransmitTime = 40
      let intpart = 0
      let fractpart = 0
      ntpClient.close()
      // Get the seconds part
      for (let i = 0; i <= 3; i++) {
        intpart = 256 * intpart + msg[offsetTransmitTime + i]
      }
      // Get the seconds fraction
      for (let i = 4; i <= 7; i++) {
        fractpart = 256 * fractpart + msg[offsetTransmitTime + i]
      }
      let milliseconds = (intpart * 1000 + (fractpart * 1000) / 0x100000000)
      let date = new Date('Jan 01 1900 GMT')
      date.setUTCMilliseconds(date.getUTCMilliseconds() + milliseconds)
      resolve(parseInt(date.getTime() / 1000))
    })
  })
}

function _writeTimeDiffToFile (timeDiff) {
  fs.writeFile(FILE_PATH, timeDiff, (err) => {
    if (err) {
      console.log(err)
    }
  })
}

/**
 * get the time difference
 */
async function refreshTimeDifference (ntpTimeServerAddress, ntpTryOut, callback) {
  let localHostTime = exports.currentUnixTimeSecond()
  let serverTime = 0
  let tryOut = 0
  let timeDiff = 0
  try {
    serverTime = await exports.asyncGetUTCTimeFromServer(ntpTimeServerAddress)
    timeDiff = localHostTime - serverTime
    _writeTimeDiffToFile()
    callback(null, timeDiff)
  } catch (err) {
    tryOut = tryOut + 1
    if (tryOut === ntpTryOut) {
      callback(serverTime, err)
      throw Error(err)
    }
    serverTime = await exports.asyncGetUTCTimeFromServer(ntpTimeServerAddress)
    timeDiff = localHostTime - serverTime
    _writeTimeDiffToFile()
    callback(null, timeDiff)
  }
}
module.exports.refreshTimeDifference = refreshTimeDifference

// -------------------------------------------------------------------------------------------------- //
// ----------------------------------------  Hash Calculations  ------------------------------------- //
// -------------------------------------------------------------------------------------------------- //

exports.hasha256 = function (data) {
  return crypto.createHash('sha256').update(data).digest()
}

/**
 * Creates SHA-3 hash of the RLP encoded version of the input
 * @param {Buffer|Array|String|Number} a the input data
 * @return {Buffer}
 */
exports.rlphash = function (a) {
  return this.keccak(rlp.encode(a))
}

/**
 * Creates Keccak hash of the input
 * @param {Buffer|Array|String|Number} a the input data
 * @param {Number} [bits=256] the Keccak width
 * @return {Buffer}
 */
exports.keccak = function (a, bits) {
  a = exports.toBuffer(a)
  if (!bits) bits = 256
  return createKeccakHash('keccak' + bits).update(a).digest()
}

/**
 * Creates Keccak-256 hash of the input, alias for keccak(a, 256)
 * @param {Buffer|Array|String|Number} a the input data
 * @return {Buffer}
 */
exports.keccak256 = function (a) {
  return exports.keccak(a)
}

/**
 * Creates SHA-3 (Keccak) hash of the input [OBSOLETE]
 * @param {Buffer|Array|String|Number} a the input data
 * @param {Number} [bits=256] the SHA-3 width
 * @return {Buffer}
 */
exports.sha3 = function (a, bits) {
  a = exports.toBuffer(a)
  if (!bits) bits = 256
  return createKeccakHash('keccak' + bits).update(a).digest()
}

/**
 * Creates SHA256 hash of the input
 * @param {Buffer|Array|String|Number} a the input data
 * @return {Buffer}
 */
exports.sha256 = function (a) {
  a = exports.toBuffer(a)
  return createHash('sha256').update(a).digest()
}

/**
 * Creates RIPEMD160 hash of the input
 * @param {Buffer|Array|String|Number} a the input data
 * @param {Boolean} padded whether it should be padded to 256 bits or not
 * @return {Buffer}
 */
exports.ripemd160 = function (a, padded) {
  a = exports.toBuffer(a)
  const hash = createHash('rmd160').update(a).digest()
  if (padded === true) {
    return exports.setLengthLeft(hash, 32)
  } else {
    return hash
  }
}

/**
 * Returns the keccak-256 hash of `message`, prefixed with the header used by the `SEC_sign` RPC call.
 * The output of this function can be fed into `ecsign` to produce the same signature as the `SEC_sign`
 * call for a given `message`, or fed to `ecrecover` along with a signature to recover the public key
 * used to produce the signature.
 * @param message
 * @returns {Buffer} hash
 */
exports.hashPersonalMessage = function (message) {
  const prefix = exports.toBuffer('\u0019SEC Signed Message:\n' + message.length.toString())
  return exports.keccak(Buffer.concat([prefix, message]))
}

exports.entropyToMnemonic = function (seed) {
  return bip39.entropyToMnemonic(seed)
}

exports.mnemonicToEntropy = function (word) {
  return bip39.mnemonicToEntropy(word)
}

// -------------------------------------------------------------------------------------------------- //
// ----------------------------------  Generate Private/Public keys  -------------------------------- //
// -------------------------------------------------------------------------------------------------- //

/**
 * generate sec private key, public key and address for a user
 */
exports.generateKeys = function () {
  // generate private key
  let addrVer = Buffer.alloc(ADDRESS_VERSION, 0x00)
  let wifByte = Buffer.alloc(1, 0x80)

  let key = ec.genKeyPair()
  let privKey = key.getPrivate().toString('hex')

  let bufPrivKey = Buffer.from(privKey, 'hex')
  let wifBufPriv = Buffer.concat([wifByte, bufPrivKey], wifByte.length + bufPrivKey.length)

  let wifHashFirst = exports.hasha256(wifBufPriv)
  let wifHashSecond = exports.hasha256(wifHashFirst)

  let wifHashSig = wifHashSecond.slice(0, 4)
  let wifBuf = Buffer.concat([wifBufPriv, wifHashSig], wifBufPriv.length + wifHashSig.length)

  let wifFinal = bs58.encode(wifBuf)
  let secWifAddress = wifFinal.toString('hex')

  // generate public key
  let pubPoint = key.getPublic()
  let publicKey = pubPoint.encode('hex')

  // generate address
  let publicKeyInitialHash = exports.hasha256(Buffer.from(publicKey, 'hex'))
  let publicKeyRIPEHash = new RIPEMD160().update(Buffer.from(publicKeyInitialHash, 'hex')).digest('hex')

  let hashBuffer = Buffer.from(publicKeyRIPEHash, 'hex')
  let concatHash = Buffer.concat([addrVer, hashBuffer], addrVer.length + hashBuffer.length)

  let hashExtRipe = exports.hasha256(concatHash)
  let hashExtRipe2 = exports.hasha256(hashExtRipe)
  let hashSig = hashExtRipe2.slice(0, 4)
  let secBinaryStr = Buffer.concat([concatHash, hashSig], concatHash.length + hashSig.length)

  let secAddress = bs58.encode(Buffer.from(secBinaryStr))

  return {
    privKey: privKey,
    secWifAddress: secWifAddress,
    publicKey: publicKey,
    secAddress: secAddress
  }
}

/**
 * Generates an address of a newly created contract
 * @param {Buffer} from the address which is creating this new address
 * @param {Buffer} nonce the nonce of the from account
 * @return {Buffer}
 */
exports.generateContractAddress = function (from, nonce) {
  from = exports.toBuffer(from)
  nonce = new BN(nonce)
  if (nonce.isZero()) {
    // in RLP we want to encode null in the case of zero nonce
    // read the RLP documentation for an answer if you dare
    nonce = null
  } else {
    nonce = Buffer.from(nonce.toArray())
  }/*  */
  // Only take the lower 160bits of the hash
  return exports.rlphash([from, nonce]).slice(-20)
}

/**
 * Defines properties on a `Object`. It make the assumption that underlying data is binary.
 * @param {Object} self the `Object` to define properties on
 * @param {Array} fields an array fields to define. Fields can contain:
 * * `name` - the name of the properties
 * * `length` - the number of bytes the field can have
 * * `allowLess` - if the field can be less than the length
 * * `allowEmpty`
 * @param {*} data data to be validated against the definitions
 */
exports.defineProperties = function (self, fields, data) {
  let raw = []
  let _fields = []

  // attach the `toJSON`
  self.toJSON = function (label) {
    if (label) {
      const obj = {}
      _fields.forEach((field) => {
        obj[field] = '0x' + self[field].toString('hex')
      })
      return obj
    }
    return exports.baToJSON(raw)
  }

  self.serialize = function serialize () {
    return rlp.encode(raw)
  }

  fields.forEach((field, i) => {
    _fields.push(field.name)
    function getter () {
      return raw[i]
    }
    function setter (v) {
      v = exports.toBuffer(v)

      if (v.toString('hex') === '00' && !field.allowZero) {
        v = Buffer.allocUnsafe(0)
      }

      if (field.allowLess && field.length) {
        v = exports.stripZeros(v)
        assert(field.length >= v.length, 'The field ' + field.name + ' must not have more ' + field.length + ' bytes')
      } else if (!(field.allowZero && v.length === 0) && field.length) {
        assert(field.length === v.length, 'The field ' + field.name + ' must have byte length of ' + field.length)
      }

      raw[i] = v
    }

    Object.defineProperty(self, field.name, {
      enumerable: true,
      configurable: true,
      get: getter,
      set: setter
    })

    if (field.default) {
      self[field.name] = field.default
    }

    // attach alias
    if (field.alias) {
      Object.defineProperty(self, field.alias, {
        enumerable: false,
        configurable: true,
        set: setter,
        get: getter
      })
    }
  })

  // if the constuctor is passed data
  if (data) {
    if (typeof data === 'string') {
      data = Buffer.from(stripHexPrefix(data), 'hex')
    }

    if (Buffer.isBuffer(data)) {
      data = rlp.decode(data)
    }

    if (Array.isArray(data)) {
      if (data.length > _fields.length) {
        throw (new Error('wrong number of fields in data'))
      }

      // make sure all the items are buffers
      data.forEach((d, i) => {
        self[_fields[i]] = exports.toBuffer(d)
      })
    } else if (typeof data === 'object') {
      const keys = Object.keys(data)
      fields.forEach((field) => {
        if (keys.indexOf(field.name) !== -1) self[field.name] = data[field.name]
        if (keys.indexOf(field.alias) !== -1) self[field.alias] = data[field.alias]
      })
    } else {
      throw new Error('invalid data')
    }
  }
}

exports.generatePrivateKey = function () {
  let key = ec.genKeyPair()
  let privKey = key.getPrivate().toString('hex')
  return privKey
}

/**
 * Returns the SEC address of a given private key
 * @param {Buffer} privateKey A private key must be 256 bits wide
 * @return {Buffer}
 */
exports.privateToAddress = function (privateKey) {
  return exports.publicToAddress(exports.privateToPublic(privateKey))
}

/**
 * Returns the SEC public key of a given private key
 * @param {Buffer} privateKey A private key must be 256 bits wide
 * @return {Buffer}
 */
exports.privateToPublic = function (privateKey) {
  privateKey = exports.toBuffer(privateKey)
  // skip the type flag and use the X, Y points
  return secp256k1.publicKeyCreate(privateKey, false).slice(1)
}

/**
 * Returns the SEC address of a given public key.
 * Accepts "SEC public keys" and SEC1 encoded keys.
 * @param {Buffer} pubKey The two points of an uncompressed key, unless sanitize is enabled
 * @param {Boolean} [sanitize=false] Accept public keys in other formats
 * @return {Buffer}
 */
exports.publicToAddress = function (pubKey, sanitize) {
  pubKey = exports.toBuffer(pubKey)
  if (sanitize && (pubKey.length !== 64)) {
    pubKey = secp256k1.publicKeyConvert(pubKey, false).slice(1)
  }
  assert(pubKey.length === 64)
  // Only take the lower 160bits of the hash
  return exports.keccak(pubKey).slice(-20)
}

/**
 * Converts a public key to the SEC format.
 * @param {Buffer} publicKey
 * @return {Buffer}
 */
exports.importPublic = function (publicKey) {
  publicKey = exports.toBuffer(publicKey)
  if (publicKey.length !== 64) {
    publicKey = secp256k1.publicKeyConvert(publicKey, false).slice(1)
  }
  return publicKey
}

/**
 * ECDSA sign
 * @param {Buffer} msgHash
 * @param {Buffer} privateKey
 * @return {Object}
 */
exports.ecsign = function (msgHash, privateKey) {
  const sig = secp256k1.sign(msgHash, privateKey)

  const ret = {}
  ret.r = sig.signature.slice(0, 32)
  ret.s = sig.signature.slice(32, 64)
  ret.v = sig.recovery + 27
  return ret
}

/**
 * ECDSA public key recovery from signature
 * @param {Buffer} msgHash
 * @param {Number} v
 * @param {Buffer} r
 * @param {Buffer} s
 * @return {Buffer} publicKey
 */
exports.ecrecover = function (msgHash, v, r, s) {
  const signature = Buffer.concat([exports.setLengthLeft(r, 32), exports.setLengthLeft(s, 32)], 64)
  const recovery = v - 27
  if (recovery !== 0 && recovery !== 1) {
    throw new Error('Invalid signature v value')
  }
  const senderPubKey = secp256k1.recover(msgHash, signature, recovery)
  return secp256k1.publicKeyConvert(senderPubKey, false).slice(1)
}

/**
 * Convert signature parameters into the format of `SEC_sign` RPC method
 * @param {Number} v
 * @param {Buffer} r
 * @param {Buffer} s
 * @return {String} sig
 */
exports.toRpcSig = function (v, r, s) {
  // NOTE: with potential introduction of chainId this might need to be updated
  if (v !== 27 && v !== 28) {
    throw new Error('Invalid recovery id')
  }

  // geth (and the RPC SEC_sign method) uses the 65 byte format used by Bitcoin
  // FIXME: this might change in the future - https://github.com/
  return exports.bufferToHex(Buffer.concat([
    exports.setLengthLeft(r, 32),
    exports.setLengthLeft(s, 32),
    exports.toBuffer(v - 27)
  ]))
}

/**
 * Convert signature format of the `SEC_sign` RPC method to signature parameters
 * NOTE: all because of a bug in geth: https://github.com/
 * @param {String} sig
 * @return {Object}
 */
exports.fromRpcSig = function (sig) {
  sig = exports.toBuffer(sig)

  // NOTE: with potential introduction of chainId this might need to be updated
  if (sig.length !== 65) {
    throw new Error('Invalid signature length')
  }

  let v = sig[64]
  // support both versions of `SEC_sign` responses
  if (v < 27) {
    v += 27
  }

  return {
    v: v,
    r: sig.slice(0, 32),
    s: sig.slice(32, 64)
  }
}

// -------------------------------------------------------------------------------------------------- //
// ------------------------------------- Verification Functions  ------------------------------------ //
// -------------------------------------------------------------------------------------------------- //

/**
 * Validate ECDSA signature
 * @method isValidSignature
 * @param {Buffer} v
 * @param {Buffer} r
 * @param {Buffer} s
 * @param {Boolean} [homestead=true]
 * @return {Boolean}
 */

exports.isValidSignature = function (v, r, s, homestead) {
  const SECP256K1_N_DIV_2 = new BN('7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0', 16)
  const SECP256K1_N = new BN('fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141', 16)

  if (r.length !== 32 || s.length !== 32) {
    return false
  }

  if (v !== 27 && v !== 28) {
    return false
  }

  r = new BN(r)
  s = new BN(s)

  if (r.isZero() || r.gt(SECP256K1_N) || s.isZero() || s.gt(SECP256K1_N)) {
    return false
  }

  if ((homestead === false) && (new BN(s).cmp(SECP256K1_N_DIV_2) === 1)) {
    return false
  }

  return true
}

/**
 * Checks if the private key satisfies the rules of the curve secp256k1.
 * @param {Buffer} privateKey
 * @return {Boolean}
 */
exports.isValidPrivate = function (privateKey) {
  return secp256k1.privateKeyVerify(privateKey)
}

/**
 * Checks if the public key satisfies the rules of the curve secp256k1
 * and the requirements of SEC.
 * @param {Buffer} publicKey The two points of an uncompressed key, unless sanitize is enabled
 * @param {Boolean} [sanitize=false] Accept public keys in other formats
 * @return {Boolean}
 */
exports.isValidPublic = function (publicKey, sanitize) {
  if (publicKey.length === 64) {
    // Convert to SEC1 for secp256k1
    return secp256k1.publicKeyVerify(Buffer.concat([Buffer.from([4]), publicKey]))
  }

  if (!sanitize) {
    return false
  }

  return secp256k1.publicKeyVerify(publicKey)
}

/**
 * Checks if the address is a valid checksummed address
 * @param {Buffer} address
 * @return {Boolean}
 */
exports.isValidChecksumAddress = function (address) {
  return exports.isValidAddress(address) && (exports.toChecksumAddress(address) === address)
}

/**
 * Returns true if the supplied address belongs to a precompiled account (Byzantium)
 * @param {Buffer|String} address
 * @return {Boolean}
 */
exports.isPrecompiled = function (address) {
  let a = exports.unpad(address)
  return a.length === 1 && a[0] >= 1 && a[0] <= 8
}

/**
 * Checks if the address is a valid. Accepts checksummed addresses too
 * @param {String} address
 * @return {Boolean}
 */
exports.isValidAddress = function (address) {
  return /^0x[0-9a-fA-F]{40}$/.test(address)
}

/**
  * Checks if a given address is a zero address
  * @method isZeroAddress
  * @param {String} address
  * @return {Boolean}
  */
exports.isZeroAddress = function (address) {
  const zeroAddress = exports.zeroAddress()
  return zeroAddress === exports.addHexPrefix(address)
}

/**
 * Returns a checksummed address
 * @param {String} address
 * @return {String}
 */
exports.toChecksumAddress = function (address) {
  address = stripHexPrefix(address).toLowerCase()
  const hash = exports.keccak(address).toString('hex')
  let ret = '0x'

  for (let i = 0; i < address.length; i++) {
    if (parseInt(hash[i], 16) >= 8) {
      ret += address[i].toUpperCase()
    } else {
      ret += address[i]
    }
  }

  return ret
}

// -------------------------------------------------------------------------------------------------- //
// ---------------------------------------  General Functions  -------------------------------------- //
// -------------------------------------------------------------------------------------------------- //

exports.padToEven = function (value) {
  let a = value; // eslint-disable-line
  if (typeof a !== 'string') {
    throw new Error(`[secjs-util] while padding to even, value must be string, is currently ${typeof a}, while padToEven.`)
  }
  if (a.length % 2) {
    a = `0${a}`
  }
  return a
}

exports.toBuffer = function (v) {
  if (!Buffer.isBuffer(v)) {
    if (Array.isArray(v)) {
      v = Buffer.from(v)
    } else if (typeof v === 'string') {
      if (exports.isHexString(v)) {
        v = Buffer.from(exports.padToEven(stripHexPrefix(v)), 'hex')
      } else {
        v = Buffer.from(v)
      }
    } else if (typeof v === 'number') {
      v = exports.intToBuffer(v)
    } else if (v === null || v === undefined) {
      v = Buffer.allocUnsafe(0)
    } else if (BN.isBN(v)) {
      v = v.toArrayLike(Buffer)
    } else if (v.toArray) {
      // converts a BN to a Buffer
      v = Buffer.from(v.toArray())
    } else {
      throw new Error('invalid type')
    }
  }
  return v
}

exports.baToJSON = function (ba) {
  if (Buffer.isBuffer(ba)) {
    return '0x' + ba.toString('hex')
  } else if (ba instanceof Array) {
    const array = []
    for (let i = 0; i < ba.length; i++) {
      array.push(exports.baToJSON(ba[i]))
    }
    return array
  }
}

exports.stripZeros = function (a) {
  a = stripHexPrefix(a)
  let first = a[0]
  while (a.length > 0 && first.toString() === '0') {
    a = a.slice(1)
    first = a[0]
  }
  return a
}

/**
 * Trims leading zeros from a `Buffer` or an `Array`
 * @param {Buffer|Array|String} a
 * @return {Buffer|Array|String}
 */
exports.unpad = function (a) {
  a = stripHexPrefix(a)
  let first = a[0]
  while (a.length > 0 && first.toString() === '0') {
    a = a.slice(1)
    first = a[0]
  }
  return a
}

/**
 * Is the string a hex string.
 *
 * @method check if string is hex string of specific length
 * @param {String} value
 * @param {Number} length
 * @returns {Boolean} output the string is a hex string
 */
exports.isHexString = function (value, length) {
  if (typeof (value) !== 'string' || !value.match(/^0x[0-9A-Fa-f]*$/)) {
    return false
  }
  if (length && value.length !== 2 + 2 * length) { return false }
  return true
}

/**
 * Converts an `Number` to a `Buffer`
 * @param {Number} i
 * @return {Buffer}
 */
exports.intToBuffer = function (i) {
  const hex = exports.intToHex(i)
  return Buffer.from(exports.padToEven(hex.slice(2)), 'hex')
}

/**
 * Converts a `Number` into a hex `String`
 * @param {Number} i
 * @return {String}
 */
exports.intToHex = function (i) {
  let hex = i.toString(16); // eslint-disable-line
  return `0x${hex}`
}

/**
 * Returns a buffer filled with 0s
 * @method zeros
 * @param {Number} bytes  the number of bytes the buffer should be
 * @return {Buffer}
 */
exports.zeros = function (bytes) {
  return Buffer.allocUnsafe(bytes).fill(0)
}

/**
 * Get the binary size of a string
 * @param {String} str
 * @return {Number}
 */
exports.getBinarySize = function (str) {
  if (typeof str !== 'string') {
    throw new Error(`[secjs-util] while getting binary size, method getBinarySize requires input 'str' to be type String, got '${typeof str}'.`)
  }

  return Buffer.byteLength(str, 'utf8')
}

/**
 * Returns TRUE if the first specified array contains all elements
 * from the second one. FALSE otherwise.
 *
 * @param {array} superset
 * @param {array} subset
 *
 * @returns {boolean}
 */
exports.arrayContainsArray = function (superset, subset, some) {
  if (Array.isArray(superset) !== true) { throw new Error(`[secjs-util] method arrayContainsArray requires input 'superset' to be an array got type '${typeof superset}'`) }
  if (Array.isArray(subset) !== true) { throw new Error(`[secjs-util] method arrayContainsArray requires input 'subset' to be an array got type '${typeof subset}'`) }

  return subset[(Boolean(some) && 'some') || 'every']((value) => (superset.indexOf(value) >= 0))
}

/**
 * Should be called to get utf8 from it's hex representation
 *
 * @method toUtf8
 * @param {String} string in hex
 * @returns {String} ascii string representation of hex value
 */
exports.toUtf8 = function (hex) {
  const bufferValue = Buffer.from(exports.padToEven(stripHexPrefix(hex).replace(/^0+|0+$/g, '')), 'hex')

  return bufferValue.toString('utf8')
}

/**
 * Should be called to get ascii from it's hex representation
 *
 * @method toAscii
 * @param {String} string in hex
 * @returns {String} ascii string representation of hex value
 */
exports.toAscii = function (hex) {
  let str = '' // eslint-disable-line
  let i = 0, l = hex.length // eslint-disable-line

  if (hex.substring(0, 2) === '0x') {
    i = 2
  }

  for (; i < l; i += 2) {
    const code = parseInt(hex.substr(i, 2), 16)
    str += String.fromCharCode(code)
  }

  return str
}

/**
 * Should be called to get hex representation (prefixed by 0x) of utf8 string
 *
 * @method fromUtf8
 * @param {String} string
 * @param {Number} optional padding
 * @returns {String} hex representation of input string
 */
exports.fromUtf8 = function (stringValue) {
  const str = Buffer.from(stringValue, 'utf8')

  return `0x${exports.padToEven(str.toString('hex')).replace(/^0+|0+$/g, '')}`
}

/**
 * Should be called to get hex representation (prefixed by 0x) of ascii string
 *
 * @method fromAscii
 * @param {String} string
 * @param {Number} optional padding
 * @returns {String} hex representation of input string
 */
exports.fromAscii = function (stringValue) {
  let hex = '' // eslint-disable-line
  for (let i = 0; i < stringValue.length; i++) { // eslint-disable-line
    const code = stringValue.charCodeAt(i)
    const n = code.toString(16)
    hex += n.length < 2 ? `0${n}` : n
  }

  return `0x${hex}`
}

/**
 * getKeys([{a: 1, b: 2}, {a: 3, b: 4}], 'a') => [1, 3]
 *
 * @method getKeys get specific key from inner object array of objects
 * @param {String} params
 * @param {String} key
 * @param {Boolean} allowEmpty
 * @returns {Array} output just a simple array of output keys
 */
exports.getKeys = function (params, key, allowEmpty) {
  if (!Array.isArray(params)) { throw new Error(`[secjs-util] method getKeys expecting type Array as 'params' input, got '${typeof params}'`) }
  if (typeof key !== 'string') { throw new Error(`[secjs-util] method getKeys expecting type String for input 'key' got '${typeof key}'.`) }

  let result = []; // eslint-disable-line

  for (let i = 0; i < params.length; i++) { // eslint-disable-line
    let value = params[i][key]; // eslint-disable-line
    if (allowEmpty && !value) {
      value = ''
    } else if (typeof (value) !== 'string') {
      throw new Error('invalid abi')
    }
    result.push(value)
  }
  return result
}

/**
 * Converts a `Buffer` into a hex `String`
 * @param {Buffer} buf
 * @return {String}
 */
exports.bufferToHex = function (buf) {
  buf = exports.toBuffer(buf)
  return '0x' + buf.toString('hex')
}

/**
  * Returns a zero address
  * @method zeroAddress
  * @return {String}
  */
exports.zeroAddress = function () {
  // address length is 20
  return exports.bufferToHex(exports.zeros(20))
}

/**
 * Left Pads an `Array` or `Buffer` with leading zeros till it has `length` bytes.
 * Or it truncates the beginning if it exceeds.
 * @method lsetLength
 * @param {Buffer|Array} msg the value to pad
 * @param {Number} length the number of bytes the output should be
 * @param {Boolean} [right=false] whether to start padding form the left or right
 * @return {Buffer|Array}
 */
exports.setLengthLeft = function (msg, length, right) {
  const buf = exports.zeros(length)
  msg = exports.toBuffer(msg)
  if (right) {
    if (msg.length < length) {
      msg.copy(buf)
      return buf
    }
    return msg.slice(0, length)
  } else {
    if (msg.length < length) {
      msg.copy(buf, length - msg.length)
      return buf
    }
    return msg.slice(-length)
  }
}

exports.setLength = function (msg, length, right) {
  const buf = exports.zeros(length)
  msg = exports.toBuffer(msg)
  if (right) {
    if (msg.length < length) {
      msg.copy(buf)
      return buf
    }
    return msg.slice(0, length)
  } else {
    if (msg.length < length) {
      msg.copy(buf, length - msg.length)
      return buf
    }
    return msg.slice(-length)
  }
}

/**
 * Right Pads an `Array` or `Buffer` with leading zeros till it has `length` bytes.
 * Or it truncates the beginning if it exceeds.
 * @param {Buffer|Array} msg the value to pad
 * @param {Number} length the number of bytes the output should be
 * @return {Buffer|Array}
 */
exports.setLengthRight = function (msg, length) {
  return exports.setLengthLeft(msg, length, true)
}

/**
 * Converts a `Buffer` to a `Number`
 * @param {Buffer} buf
 * @return {Number}
 * @throws If the input number exceeds 53 bits.
 */
exports.bufferToInt = function (buf) {
  return new BN(exports.toBuffer(buf)).toNumber()
}

/**
 * Interprets a `Buffer` as a signed integer and returns a `BN`. Assumes 256-bit numbers.
 * @param {Buffer} num
 * @return {BN}
 */
exports.fromSigned = function (num) {
  return new BN(num).fromTwos(256)
}

/**
 * Converts a `BN` to an unsigned integer and returns it as a `Buffer`. Assumes 256-bit numbers.
 * @param {BN} num
 * @return {Buffer}
 */
exports.toUnsigned = function (num) {
  return Buffer.from(num.toTwos(256).toArray())
}

/**
 * Adds "0x" to a given `String` if it does not already start with "0x"
 * @param {String} str
 * @return {String}
 */
exports.addHexPrefix = function (str) {
  if (typeof str !== 'string') {
    return str
  }

  return isHexPrefixed(str) ? str : '0x' + str
}

exports.stripHexPrefix = function (str) {
  if (typeof str !== 'string') {
    return str
  }
  return isHexPrefixed(str) ? str.slice(2) : str
}
