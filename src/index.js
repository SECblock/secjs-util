'strict mode'
const secp256k1 = require('secp256k1')
const createKeccakHash = require('keccak')
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

  padToEven (value) {
    let a = value; // eslint-disable-line
    if (typeof a !== 'string') {
      throw new Error(`[ethjs-util] while padding to even, value must be string, is currently ${typeof a}, while padToEven.`)
    }
    if (a.length % 2) {
      a = `0${a}`
    }
    return a
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
}

module.exports = SecUtils
