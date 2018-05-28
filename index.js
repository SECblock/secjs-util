class SecUtil {
  constructor () {
    this.date = ''
    this.CurrentUnixTime = ''
    this.CurrentDateTime = ''
  }
  UnixTime () {
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
   * @param  {text} a -test parameter a
   */
  DateTime () {
    try {
      let date = new Date()
      this.CurrentUnixTime = date.getTime()
      let CurrentUnixTime = this.CurrentUnixTime
      this.CurrentDateTime = new Date(CurrentUnixTime).toUTCString()
    } catch (e) {
      console.log('ERROR：' + e)
    }
    return this.CurrentDateTime
  }
}

module.exports = SecUtil

// class SecUtil {
//   constructor () {
//     this.date = ''
//     this.CurrentUnixTime = ''
//     this.CurrentDateTime = ''
//   }
//   UnixTime () {
//     let date = new Date()
//     this.CurrentUnixTime = date.getTime()
//     let CurrentUnixTime = this.CurrentUnixTime

//     return CurrentUnixTime
//   }
//   DateTime () {
//     let date = new Date()
//     this.CurrentUnixTime = date.getTime()
//     let CurrentUnixTime = this.CurrentUnixTime
//     this.CurrentDateTime = new Date(CurrentUnixTime).toUTCString()
//     let CurrentDateTime = this.CurrentDateTime

//     return CurrentDateTime
//   }
// }

// module.exports = SecUtil
