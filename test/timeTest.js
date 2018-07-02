const SecUtils = require('../src/index')
const util = new SecUtils()

let a = util.currentUnixTimeInMillisecond()
console.log('current Unix time is ' + a)
// let b = util.DateTime()
// console.log('GMT standard time is ' + b)

let b = 1527717126082 // any unix time
let c = util.getDatetime(b)
console.log('convert to datetime ' + c)

// let anyUnixtime = new Date('1398250549123')
// let time1 = util.getUnixtime(anyUnixtime)
// console.log(time1)

let d = '2014-04-23 18:55:49:123' // any date time
let e = util.getUnixtime(d)
console.log('convert to unixtime ' + e)

util.refreshTimeDifference((err, timeDiff) => {
  if (err) {
    console.log(err)
  }
  console.log(timeDiff)
})
