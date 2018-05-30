class SecUtils {
  constructor () {
    this.date = ''
    this.CurrentUnixTime = ''
    this.CurrentDateTime = ''
  }
  currentUnixTime () {
    try {
      let date = new Date()
      this.CurrentUnixTime = date.getTime()
      // var CurrentUnixTime = this.CurrentUnixTime
    } catch (e) {
      console.log('ERROR：' + e)
    }
    return this.CurrentUnixTime
  }
  /**
   * @param  {text}
   */
  getUnixTime(_date) {
    let unixtime = convert(_date)
    return unixtime
  }

  getDatetime(unixtime) {
    let date = converttodate(unixtime)
    return date
  }


   // DateTime () {
  //   try {
  //     let date = new Date()
  //     this.CurrentUnixTime = date.getTime()
  //     let CurrentUnixTime = this.CurrentUnixTime
  //     this.CurrentDateTime = new Date(CurrentUnixTime).toUTCString()
  //   } catch (e) {
  //     console.log('ERROR：' + e)
  //   }
  //   return this.CurrentDateTime
  // }


}

module.exports = SecUtils

//
let futureDatetime = new Date('2018-10-01')
let SECUtil = require('./index.js')
let futureUnixtime = SECUtil.getUnixTime(futureDatetime) //84161654879

