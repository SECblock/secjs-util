const SecUtils = require('../src/index')
const utils = new SecUtils()

let blockheader = function (data, opts) {
  opts = opts || {}

  if (opts.common) {
    if (opts.chain) {
      throw new Error('Instantiation with both opts.common and opts.chain parameter not allowed!')
    }
    this._common = opts.common
  } else {
    let chain = opts.chain ? opts.chain : 'mainnet'
    let hardfork = opts.hardfork ? opts.hardfork : null
    this._common = new Common(chain, hardfork)
  }

  let fields = [{
    name: 'parentHash',
    length: 32,
    default: utils.zeros(32)
  }, {
    name: 'uncleHash',
    default: utils.SHA3_RLP_ARRAY
  }, {
    name: 'coinbase',
    length: 20,
    default: utils.zeros(20)
  }, {
    name: 'stateRoot',
    length: 32,
    default: utils.zeros(32)
  }, {
    name: 'transactionsTrie',
    length: 32,
    default: utils.SHA3_RLP
  }, {
    name: 'receiptTrie',
    length: 32,
    default: utils.SHA3_RLP
  }, {
    name: 'bloom',
    default: utils.zeros(256)
  }, {
    name: 'difficulty',
    default: Buffer.from([])
  }, {
    name: 'number',
    // TODO: params.homeSteadForkNumber.v left for legacy reasons, replace on future release
    default: utils.intToBuffer(1150000)
  }, {
    name: 'gasLimit',
    default: Buffer.from('ffffffffffffff', 'hex')
  }, {
    name: 'gasUsed',
    empty: true,
    default: Buffer.from([])
  }, {
    name: 'timestamp',
    default: Buffer.from([])
  }, {
    name: 'extraData',
    allowZero: true,
    empty: true,
    default: Buffer.from([])
  }, {
    name: 'mixHash',
    default: utils.zeros(32)
    // length: 32
  }, {
    name: 'nonce',
    default: utils.zeros(8) // sha3(42)
  }]
  utils.defineProperties(this, fields, data)
}

console.log(utils.rlphash('teststring'))
