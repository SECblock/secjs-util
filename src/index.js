
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

class SecUtils {
  constructor (config = { timeServer: 'DE' }) {
    /**
     * the max integer that this VM can handle (a ```BN```)
     * @var {BN} MAX_INTEGER
     */
    this.MAX_INTEGER = new BN('ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff', 16)

    /**
     * 2^256 (a ```BN```)
     * @var {BN} TWO_POW256
     */
    this.TWO_POW256 = new BN('10000000000000000000000000000000000000000000000000000000000000000', 16)

    /**
     * Keccak-256 hash of null (a ```String```)
     * @var {String} KECCAK256_NULL_S
     */
    this.KECCAK256_NULL_S = 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470'
    this.SHA3_NULL_S = this.KECCAK256_NULL_S

    /**
     * Keccak-256 hash of null (a ```Buffer```)
     * @var {Buffer} KECCAK256_NULL
     */
    this.KECCAK256_NULL = Buffer.from(this.KECCAK256_NULL_S, 'hex')
    this.SHA3_NULL = this.KECCAK256_NULL

    /**
     * Keccak-256 of an RLP of an empty array (a ```String```)
     * @var {String} KECCAK256_RLP_ARRAY_S
     */
    this.KECCAK256_RLP_ARRAY_S = '1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347'
    this.SHA3_RLP_ARRAY_S = this.KECCAK256_RLP_ARRAY_S

    /**
     * Keccak-256 of an RLP of an empty array (a ```Buffer```)
     * @var {Buffer} KECCAK256_RLP_ARRAY
     */
    this.KECCAK256_RLP_ARRAY = Buffer.from(this.KECCAK256_RLP_ARRAY_S, 'hex')
    this.SHA3_RLP_ARRAY = this.KECCAK256_RLP_ARRAY

    /**
     * Keccak-256 hash of the RLP of null  (a ```String```)
     * @var {String} KECCAK256_RLP_S
     */
    this.KECCAK256_RLP_S = '56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421'
    this.SHA3_RLP_S = this.KECCAK256_RLP_S

    /**
     * Keccak-256 hash of the RLP of null (a ```Buffer```)
     * @var {Buffer} KECCAK256_RLP
     */
    this.KECCAK256_RLP = Buffer.from(this.KECCAK256_RLP_S, 'hex')
    this.SHA3_RLP = this.KECCAK256_RLP

    this.BN = BN
    this.secp256k1 = secp256k1
    this.rlp = rlp

    this.date = ''
    this.CurrentUnixtime = ''
    this.currentUnixTimeInSecond = ''
    this.unixtime = ''
    this.datetime = ''
    this.timeDiff = 0 // time difference between server and local host
    this.privKey = ''
    this.publicKey = ''
    this.secWifAddress = ''
    this.secAddress = ''
    this.filePath = process.cwd() + 'timeDiff.txt'
    switch (config.timeServer) {
      case 'USA':
        this.ntpTimeServerAddress = 'us.pool.ntp.org'
        break
      case 'DE':
        this.ntpTimeServerAddress = 'de.pool.ntp.org'
        break
      case 'ZH':
        this.ntpTimeServerAddress = 'cn.pool.ntp.org'
        break
      default:
        this.ntpTimeServerAddress = 'de.pool.ntp.org'
        break
    }
    this.generatePrivateKey()
  }

  currentUnixTimeInMillisecond () {
    try {
      let date = new Date()
      this.CurrentUnixtime = date.getTime()
    } catch (e) {
      console.log('ERROR：' + e)
    }
    return this.CurrentUnixtime
  }

  /**
   * @param  {} anyUnixtime = unix time in number
   * @param  {} datetime=convert to date time
   */
  getDatetime (anyUnixtime) {
    let date = new Date(anyUnixtime)
    let Y = date.getFullYear() + '-'
    let M = (date.getMonth() + 1 < 10 ? '0' + (date.getMonth() + 1) : date.getMonth() + 1) + '-'
    let D = date.getDate() + ' '
    let h = date.getHours() + ':'
    let m = date.getMinutes() + ':'
    let s = date.getSeconds()
    this.datetime = Y + M + D + h + m + s
    return this.datetime
  }

  currentUnixTimeSecond () {
    this.currentUnixTimeInSecond = Math.round(this.currentUnixTimeInMillisecond() / 1000)
    return this.currentUnixTimeInSecond
  }

  /**
   * @param  {} anyDate= date time in String,'YYYY MM DD HH:MM:SS:MS'
   * @param  {} this.unixtime=convert to unix time
   */
  getUnixtime (anyDate) {
    let date = new Date(anyDate.replace(/-/g, '/'))
    this.unixtime = date.getTime()
    return this.unixtime
  }

  /**
  //  * get unix time from time server
  //  * @return {Promise}
  //  */
  asyncGetUTCTimeFromServer () {
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

      ntpClient.send(ntpData, ntpPort, this.ntpTimeServerAddress, (err) => {
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

  /**
   * get the time difference
   */
  async refreshTimeDifference (callback) {
    let localHostTime = this.currentUnixTimeSecond()
    let serverTime = 0
    let tryOut = 0
    try {
      serverTime = await this.asyncGetUTCTimeFromServer()
      this.timeDiff = localHostTime - serverTime
      this._writeTimeDiffToFile()
      callback(null, this.timeDiff)
    } catch (err) {
      tryOut = tryOut + 1
      if (tryOut === this.ntpTryOut) {
        callback(serverTime, err)
        throw Error(err)
      }
      serverTime = await this.asyncGetUTCTimeFromServer()
      this.timeDiff = localHostTime - serverTime
      this._writeTimeDiffToFile()
      callback(null, this.timeDiff)
    }
  }

  _writeTimeDiffToFile () {
    fs.writeFile(this.filePath, this.timeDiff, (err) => {
      if (err) {
        console.log(err)
      }
    })
  }

  // CryptoSignature (msgHash, v, r, s) {
  //   const signature = Buffer.concat([this.setLength(r, 32), this.setLength(s, 32)], 64)
  //   const recovery = v - 27
  //   if (recovery !== 0 && recovery !== 1) {
  //     throw new Error('Invalid signature v value')
  //   }
  //   const senderPubKey = secp256k1.recover(msgHash, signature, recovery)
  //   return secp256k1.publicKeyConvert(senderPubKey, false).slice(1)

  /**
   * A small function created as there is a lot of sha256 hashing.
   * @param  {Buffer} data -creat sha256 hash buffer
   */

  hasha256 (data) {
    return crypto.createHash('sha256').update(data).digest()
  }
  /**
   * 0x00 P2PKH Mainnet, 0x6f P2PKH Testnet
   * 0x80 Mainnet, 0xEF Testnet （or Test Network: 0x6f and Namecoin Net:0x34）
   * generate private key through sha256 random values. and translate to hex
   * get usedful private key. It will be used for secp256k1
   * generate check code. two times SHA256 at privatKey.
   * base58(privat key + the version number + check code).
   * it is used as WIF(Wallet import Format) privatKey
   */
  generatePrivateKey () {
    let addrVer = Buffer.alloc(1, 0x00)
    let wifByte = Buffer.alloc(1, 0x80)

    let key = ec.genKeyPair()
    this.privKey = key.getPrivate().toString('hex')

    let bufPrivKey = Buffer.from(this.privKey, 'hex')
    let wifBufPriv = Buffer.concat([wifByte, bufPrivKey], wifByte.length + bufPrivKey.length)

    let wifHashFirst = this.hasha256(wifBufPriv)
    let wifHashSecond = this.hasha256(wifHashFirst)

    let wifHashSig = wifHashSecond.slice(0, 4)
    let wifBuf = Buffer.concat([wifBufPriv, wifHashSig], wifBufPriv.length + wifHashSig.length)

    let wifFinal = bs58.encode(wifBuf)
    this.secWifAddress = wifFinal.toString('hex')
    this.generatePublicKey(key, addrVer)
  }

  /**
   * generate public key
   * @param  {Buffer} key
   * @param  {Buffer} addrVer -input addVer from generatePrivateKey()
   * set elliptic point and x,y axis
   * not sure whether useful
   * let x = pubPoint.getX()
   * let y = pubPoint.getY()
   * use secp256k1. generate public key
   * structe public key: 1(network ID) + 32bytes(from x axis) + 32bytes(from y axis)
   * ripemd160(sha256(public key))
   */
  generatePublicKey (key, addrVer) {
    let pubPoint = key.getPublic()

    this.publicKey = pubPoint.encode('hex')
    this.generateAddress(this.publicKey, addrVer)
  }

  /**
   * double sha256 generate hashExtRipe2. sha256(sha256(version number + hashBuffer)).
   * the first 4 bytes of hashExtRipe2 are used as a checksum and placed at the end of
   * the 21 byte array. structe secBinary: 1(network ID) + concatHash + 4 byte(checksum)
   * @param  {Buffer} publicKey -input public key from generatePublicKey()
   * @param  {Buffer} addrVer -input addVer from generatePrivateKey()
   * generate WIF private key and translate to hex
   * generate SEC Address and translate to hex
   */
  generateAddress (publicKey, addrVer) {
    let publicKeyInitialHash = this.hasha256(Buffer.from(publicKey, 'hex'))
    let publicKeyRIPEHash = new RIPEMD160().update(Buffer.from(publicKeyInitialHash, 'hex')).digest('hex')

    let hashBuffer = Buffer.from(publicKeyRIPEHash, 'hex')
    let concatHash = Buffer.concat([addrVer, hashBuffer], addrVer.length + hashBuffer.length)

    let hashExtRipe = this.hasha256(concatHash)
    let hashExtRipe2 = this.hasha256(hashExtRipe)
    let hashSig = hashExtRipe2.slice(0, 4)
    let secBinaryStr = Buffer.concat([concatHash, hashSig], concatHash.length + hashSig.length)

    this.secAddress = bs58.encode(Buffer.from(secBinaryStr))
  }

  /**
   * return four private key, wif private key, public key
   * and sec address
   */
  getPrivateKey () {
    return this.privKey
  }

  getsecWifFinal () {
    return this.secWifAddress
  }

  getPublicKey () {
    return this.publicKey
  }

  getAddress () {
    return this.secAddress
  }

  /**
   * sec-block supporting utils
   */

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
  defineProperties (self, fields, data) {
    self.raw = []
    self._fields = []
    self.toBuffer = this.toBuffer
    self.stripZero = this.stripZero

    // attach the `toJSON`
    self.toJSON = function (label) {
      if (label) {
        const obj = {}
        self._fields.forEach((field) => {
          obj[field] = '0x' + self[field].toString('hex')
        })
        return obj
      }
      return this.baToJSON(this.raw)
    }

    self.serialize = function serialize () {
      return rlp.encode(self.raw)
    }

    fields.forEach((field, i) => {
      self._fields.push(field.name)
      function getter () {
        return self.raw[i]
      }
      function setter (v) {
        v = this.toBuffer(v)

        if (v.toString('hex') === '00' && !field.allowZero) {
          v = Buffer.allocUnsafe(0)
        }

        if (field.allowLess && field.length) {
          v = this.stripZeros(v)
          assert(field.length >= v.length, 'The field ' + field.name + ' must not have more ' + field.length + ' bytes')
        } else if (!(field.allowZero && v.length === 0) && field.length) {
          assert(field.length === v.length, 'The field ' + field.name + ' must have byte length of ' + field.length)
        }

        self.raw[i] = v
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
        if (data.length > self._fields.length) {
          throw (new Error('wrong number of fields in data'))
        }

        // make sure all the items are buffers
        data.forEach((d, i) => {
          self[self._fields[i]] = this.toBuffer(d)
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

  padToEven (value) {
    let a = value; // eslint-disable-line
    if (typeof a !== 'string') {
      throw new Error(`[secjs-util] while padding to even, value must be string, is currently ${typeof a}, while padToEven.`)
    }
    if (a.length % 2) {
      a = `0${a}`
    }
    return a
  }

  toBuffer (v) {
    if (!Buffer.isBuffer(v)) {
      if (Array.isArray(v)) {
        v = Buffer.from(v)
      } else if (typeof v === 'string') {
        if (this.isHexString(v)) {
          v = Buffer.from(this.padToEven(stripHexPrefix(v)), 'hex')
        } else {
          v = Buffer.from(v)
        }
      } else if (typeof v === 'number') {
        v = this.intToBuffer(v)
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

  baToJSON (ba) {
    if (Buffer.isBuffer(ba)) {
      return '0x' + ba.toString('hex')
    } else if (ba instanceof Array) {
      const array = []
      for (let i = 0; i < ba.length; i++) {
        array.push(this.baToJSON(ba[i]))
      }
      return array
    }
  }

  stripZeros (a) {
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
  unpad (a) {
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
  isHexString (value, length) {
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
  intToBuffer (i) {
    const hex = this.intToHex(i)
    return new Buffer(this.padToEven(hex.slice(2)), 'hex')
  }

  /**
   * Converts a `Number` into a hex `String`
   * @param {Number} i
   * @return {String}
   */
  intToHex (i) {
    let hex = i.toString(16); // eslint-disable-line
    return `0x${hex}`
  }

  /**
   * Creates SHA-3 hash of the RLP encoded version of the input
   * @param {Buffer|Array|String|Number} a the input data
   * @return {Buffer}
   */
  rlphash (a) {
    return this.keccak(rlp.encode(a))
  }

  /**
   * Creates Keccak hash of the input
   * @param {Buffer|Array|String|Number} a the input data
   * @param {Number} [bits=256] the Keccak width
   * @return {Buffer}
   */
  keccak (a, bits) {
    a = this.toBuffer(a)
    if (!bits) bits = 256
    return createKeccakHash('keccak' + bits).update(a).digest()
  }

  /**
   * Returns a buffer filled with 0s
   * @method zeros
   * @param {Number} bytes  the number of bytes the buffer should be
   * @return {Buffer}
   */
  zeros (bytes) {
    return Buffer.allocUnsafe(bytes).fill(0)
  }

  /**
 * Get the binary size of a string
 * @param {String} str
 * @return {Number}
 */
  getBinarySize (str) {
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
  arrayContainsArray (superset, subset, some) {
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
  toUtf8 (hex) {
    const bufferValue = new Buffer(this.padToEven(stripHexPrefix(hex).replace(/^0+|0+$/g, '')), 'hex')

    return bufferValue.toString('utf8')
  }

  /**
   * Should be called to get ascii from it's hex representation
   *
   * @method toAscii
   * @param {String} string in hex
   * @returns {String} ascii string representation of hex value
   */
  toAscii (hex) {
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
  fromUtf8 (stringValue) {
    const str = new Buffer(stringValue, 'utf8')

    return `0x${this.padToEven(str.toString('hex')).replace(/^0+|0+$/g, '')}`
  }

  /**
   * Should be called to get hex representation (prefixed by 0x) of ascii string
   *
   * @method fromAscii
   * @param {String} string
   * @param {Number} optional padding
   * @returns {String} hex representation of input string
   */
  fromAscii (stringValue) {
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
  getKeys (params, key, allowEmpty) {
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
  bufferToHex (buf) {
    buf = this.toBuffer(buf)
    return '0x' + buf.toString('hex')
  }
  /**
    * Returns a zero address
    * @method zeroAddress
    * @return {String}
    */
  zeroAddress () {
    const addressLength = 20
    const zeroAddress = this.zeros(addressLength)
    return this.bufferToHex(zeroAddress)
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
  setLengthLeft (msg, length, right) {
    const buf = this.zeros(length)
    msg = this.toBuffer(msg)
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

  setLength (msg, length, right) {
    const buf = this.zeros(length)
    msg = this.toBuffer(msg)
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
  setLengthRight (msg, length) {
    return this.setLengthLeft(msg, length, true)
  }

  /**
   * Converts a `Buffer` to a `Number`
   * @param {Buffer} buf
   * @return {Number}
   * @throws If the input number exceeds 53 bits.
   */
  bufferToInt (buf) {
    return new BN(this.toBuffer(buf)).toNumber()
  }

  /**
   * Interprets a `Buffer` as a signed integer and returns a `BN`. Assumes 256-bit numbers.
   * @param {Buffer} num
   * @return {BN}
   */
  fromSigned (num) {
    return new BN(num).fromTwos(256)
  }

  /**
   * Converts a `BN` to an unsigned integer and returns it as a `Buffer`. Assumes 256-bit numbers.
   * @param {BN} num
   * @return {Buffer}
   */
  toUnsigned (num) {
    return Buffer.from(num.toTwos(256).toArray())
  }

  /**
   * Creates Keccak-256 hash of the input, alias for keccak(a, 256)
   * @param {Buffer|Array|String|Number} a the input data
   * @return {Buffer}
   */
  keccak256 (a) {
    return this.keccak(a)
  }

  /**
   * Creates SHA-3 (Keccak) hash of the input [OBSOLETE]
   * @param {Buffer|Array|String|Number} a the input data
   * @param {Number} [bits=256] the SHA-3 width
   * @return {Buffer}
   */
  sha3 (a, bits) {
    a = this.toBuffer(a)
    if (!bits) bits = 256
    return createKeccakHash('keccak' + bits).update(a).digest()
  }

  /**
   * Creates SHA256 hash of the input
   * @param {Buffer|Array|String|Number} a the input data
   * @return {Buffer}
   */
  sha256 (a) {
    a = this.toBuffer(a)
    return createHash('sha256').update(a).digest()
  }

  /**
   * Creates RIPEMD160 hash of the input
   * @param {Buffer|Array|String|Number} a the input data
   * @param {Boolean} padded whether it should be padded to 256 bits or not
   * @return {Buffer}
   */
  ripemd160 (a, padded) {
    a = this.toBuffer(a)
    const hash = createHash('rmd160').update(a).digest()
    if (padded === true) {
      return this.setLengthLeft(hash, 32)
    } else {
      return hash
    }
  }

  /**
   * Checks if the private key satisfies the rules of the curve secp256k1.
   * @param {Buffer} privateKey
   * @return {Boolean}
   */
  isValidPrivate (privateKey) {
    return secp256k1.privateKeyVerify(privateKey)
  }

  /**
   * Checks if the public key satisfies the rules of the curve secp256k1
   * and the requirements of SEC.
   * @param {Buffer} publicKey The two points of an uncompressed key, unless sanitize is enabled
   * @param {Boolean} [sanitize=false] Accept public keys in other formats
   * @return {Boolean}
   */
  isValidPublic (publicKey, sanitize) {
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
   * Returns the SEC address of a given public key.
   * Accepts "SEC public keys" and SEC1 encoded keys.
   * @param {Buffer} pubKey The two points of an uncompressed key, unless sanitize is enabled
   * @param {Boolean} [sanitize=false] Accept public keys in other formats
   * @return {Buffer}
   */
  publicToAddress (pubKey, sanitize) {
    pubKey = this.toBuffer(pubKey)
    if (sanitize && (pubKey.length !== 64)) {
      pubKey = secp256k1.publicKeyConvert(pubKey, false).slice(1)
    }
    assert(pubKey.length === 64)
    // Only take the lower 160bits of the hash
    return this.keccak(pubKey).slice(-20)
  }

  /**
   * Returns the SEC public key of a given private key
   * @param {Buffer} privateKey A private key must be 256 bits wide
   * @return {Buffer}
   */
  privateToPublic (privateKey) {
    privateKey = this.toBuffer(privateKey)
    // skip the type flag and use the X, Y points
    return secp256k1.publicKeyCreate(privateKey, false).slice(1)
  }

  /**
   * Converts a public key to the SEC format.
   * @param {Buffer} publicKey
   * @return {Buffer}
   */
  importPublic (publicKey) {
    publicKey = this.toBuffer(publicKey)
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
  ecsign (msgHash, privateKey) {
    const sig = secp256k1.sign(msgHash, privateKey)

    const ret = {}
    ret.r = sig.signature.slice(0, 32)
    ret.s = sig.signature.slice(32, 64)
    ret.v = sig.recovery + 27
    return ret
  }

  /**
   * Returns the keccak-256 hash of `message`, prefixed with the header used by the `SEC_sign` RPC call.
   * The output of this function can be fed into `ecsign` to produce the same signature as the `SEC_sign`
   * call for a given `message`, or fed to `ecrecover` along with a signature to recover the public key
   * used to produce the signature.
   * @param message
   * @returns {Buffer} hash
   */
  hashPersonalMessage (message) {
    const prefix = this.toBuffer('\u0019Ethereum Signed Message:\n' + message.length.toString())
    return this.keccak(Buffer.concat([prefix, message]))
  }

  /**
   * ECDSA public key recovery from signature
   * @param {Buffer} msgHash
   * @param {Number} v
   * @param {Buffer} r
   * @param {Buffer} s
   * @return {Buffer} publicKey
   */
  ecrecover (msgHash, v, r, s) {
    const signature = Buffer.concat([this.setLengthLeft(r, 32), this.setLengthLeft(s, 32)], 64)
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
  toRpcSig (v, r, s) {
    // NOTE: with potential introduction of chainId this might need to be updated
    if (v !== 27 && v !== 28) {
      throw new Error('Invalid recovery id')
    }

    // geth (and the RPC SEC_sign method) uses the 65 byte format used by Bitcoin
    // FIXME: this might change in the future - https://github.com/
    return this.bufferToHex(Buffer.concat([
      this.setLengthLeft(r, 32),
      this.setLengthLeft(s, 32),
      this.toBuffer(v - 27)
    ]))
  }

  /**
   * Convert signature format of the `SEC_sign` RPC method to signature parameters
   * NOTE: all because of a bug in geth: https://github.com/
   * @param {String} sig
   * @return {Object}
   */
  fromRpcSig (sig) {
    sig = this.toBuffer(sig)

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

  /**
   * Returns the SEC address of a given private key
   * @param {Buffer} privateKey A private key must be 256 bits wide
   * @return {Buffer}
   */
  privateToAddress (privateKey) {
    return this.publicToAddress(this.privateToPublic(privateKey))
  }

  /**
   * Checks if the address is a valid. Accepts checksummed addresses too
   * @param {String} address
   * @return {Boolean}
   */
  isValidAddress (address) {
    return /^0x[0-9a-fA-F]{40}$/.test(address)
  }

  /**
    * Checks if a given address is a zero address
    * @method isZeroAddress
    * @param {String} address
    * @return {Boolean}
    */
  isZeroAddress (address) {
    const zeroAddress = this.zeroAddress()
    return zeroAddress === this.addHexPrefix(address)
  }

  /**
   * Returns a checksummed address
   * @param {String} address
   * @return {String}
   */
  toChecksumAddress (address) {
    address = stripHexPrefix(address).toLowerCase()
    const hash = this.keccak(address).toString('hex')
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

  /**
   * Checks if the address is a valid checksummed address
   * @param {Buffer} address
   * @return {Boolean}
   */
  isValidChecksumAddress (address) {
    return this.isValidAddress(address) && (this.toChecksumAddress(address) === address)
  }

  /**
   * Generates an address of a newly created contract
   * @param {Buffer} from the address which is creating this new address
   * @param {Buffer} nonce the nonce of the from account
   * @return {Buffer}
   */
  generateContractAddress (from, nonce) {
    from = this.toBuffer(from)
    nonce = new BN(nonce)
    if (nonce.isZero()) {
      // in RLP we want to encode null in the case of zero nonce
      // read the RLP documentation for an answer if you dare
      nonce = null
    } else {
      nonce = Buffer.from(nonce.toArray())
    }/*  */
    // Only take the lower 160bits of the hash
    return this.rlphash([from, nonce]).slice(-20)
  }

  /**
   * Returns true if the supplied address belongs to a precompiled account (Byzantium)
   * @param {Buffer|String} address
   * @return {Boolean}
   */
  isPrecompiled (address) {
    let a = this.unpad(address)
    return a.length === 1 && a[0] >= 1 && a[0] <= 8
  }

  /**
   * Adds "0x" to a given `String` if it does not already start with "0x"
   * @param {String} str
   * @return {String}
   */
  addHexPrefix (str) {
    if (typeof str !== 'string') {
      return str
    }

    return isHexPrefixed(str) ? str : '0x' + str
  }

  /**
   * Validate ECDSA signature
   * @method isValidSignature
   * @param {Buffer} v
   * @param {Buffer} r
   * @param {Buffer} s
   * @param {Boolean} [homestead=true]
   * @return {Boolean}
   */

  isValidSignature (v, r, s, homestead) {
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
  stripHexPrefix (str) {
    if (typeof str !== 'string') {
      return str
    }
    return isHexPrefixed(str) ? str.slice(2) : str
  }
  entropyToMnemonic (seed) {
    return bip39.entropyToMnemonic(seed)
  }

  mnemonicToEntropy (word) {
    return bip39.mnemonicToEntropy(word)
  }
}

module.exports = SecUtils
