const secp256k1 = require('secp256k1')
const rlp = require('rlp')
const BN = require('bn.js')

exports.BN = BN
exports.secp256k1 = secp256k1
exports.rlp = rlp

class SecUtils {
  constructor () {
    this.date = ''
    this.CurrentUnixtime = ''
    this.unixtime = ''
    this.datetime = ''
  }
  currentUnixtime () {
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
    let M = (date.getMonth() + 1 < 10 ? '0' + (date.getMonth() + 1) : date.getMonth() + 1) + '-';
    let D = date.getDate() + ' '
    let h = date.getHours() + ':'
    let m = date.getMinutes() + ':'
    let s = date.getSeconds()
    this.datetime = Y + M + D + h + m + s
    return this.datetime
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
  // CryptoSignature (msgHash, v, r, s) {
  //   const signature = Buffer.concat([exports.setLength(r, 32), exports.setLength(s, 32)], 64)
  //   const recovery = v - 27
  //   if (recovery !== 0 && recovery !== 1) {
  //     throw new Error('Invalid signature v value')
  //   }
  //   const senderPubKey = secp256k1.recover(msgHash, signature, recovery)
  //   return secp256k1.publicKeyConvert(senderPubKey, false).slice(1)
}

module.exports = SecUtils
