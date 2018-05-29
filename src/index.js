class SecUtils {
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
   * @param  {text}
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

module.exports = SecUtils
