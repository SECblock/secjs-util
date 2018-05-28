const SecUtil = require('./index.js')
const Utils = new SecUtil()

let a = Utils.UnixTime()
console.log(a)

let b = Utils.DateTime()
console.log(b)
