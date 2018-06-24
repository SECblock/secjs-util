'strict mode'
const secp256k1 = require('secp256k1')
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

exports.BN = BN
exports.secp256k1 = secp256k1
exports.rlp = rlp

class SecUtils {
  constructor (config) {
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
        for (var i = 0; i <= 3; i++) {
          intpart = 256 * intpart + msg[offsetTransmitTime + i]
        }
        // Get the seconds fraction
        for (i = 4; i <= 7; i++) {
          fractpart = 256 * fractpart + msg[offsetTransmitTime + i]
        }
        let milliseconds = (intpart * 1000 + (fractpart * 1000) / 0x100000000)
        var date = new Date('Jan 01 1900 GMT')
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
  //   const signature = Buffer.concat([exports.setLength(r, 32), exports.setLength(s, 32)], 64)
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
}

module.exports = SecUtils
