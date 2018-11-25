const SecUtil = require('../src/index')
const assert = require('chai').assert
const BN = require('bn.js')
const Buffer = require('safe-buffer').Buffer
const expect = require('chai').expect

describe('currentUnixTimeInMillisecond', function () {
  it('should generate a unix timestamp in ms', () => {
    SecUtil.currentUnixTimeInMillisecond(function (value) {
      expect(value).to.equal(1530641896147)
    })
  })
})

describe('currentUnixTimeSecond', function () {
  it('should generate a unix timestamp in s', () => {
    SecUtil.currentUnixTimeSecond(function (value) {
      expect(value).to.equal(1530973479)
    })
  })
})

describe('zeros function', function () {
  it('should produce lots of 0s', function () {
    let z60 = SecUtil.zeros(30)
    let zs60 = '000000000000000000000000000000000000000000000000000000000000'
    assert.equal(z60.toString('hex'), zs60)
  })
})

describe('zero address', function () {
  it('should generate a zero address', function () {
    let zeroAddress = SecUtil.zeroAddress()
    assert.equal(zeroAddress, '0x0000000000000000000000000000000000000000')
  })
})

describe('is zero address', function () {
  it('should return true when a zero address is passed', function () {
    let isZeroAddress = SecUtil.isZeroAddress('0x0000000000000000000000000000000000000000')
    assert.equal(isZeroAddress, true)
  })

  it('should return false when the address is not equal to zero', function () {
    let nonZeroAddress = '0x2f015c60e0be116b1f0cd534704db9c92118fb6a'
    assert.equal(SecUtil.isZeroAddress(nonZeroAddress), false)
  })
})

describe('keccak', function () {
  it('should produce a hash', function () {
    let msg = '0x3c9229289a6125f7fdf1885a77bb12c37a8d3b4962d936f7e3084dece32a3ca1'
    let r = '82ff40c0a986c6a5cfad4ddf4c3aa6996f1a7837f9c398e17e5de5cbd5a12b28'
    let hash = SecUtil.keccak(msg)
    assert.equal(hash.toString('hex'), r)
  })
})

describe('keccak256', function () {
  it('should produce a hash (keccak(a, 256) alias)', function () {
    let msg = '0x3c9229289a6125f7fdf1885a77bb12c37a8d3b4962d936f7e3084dece32a3ca1'
    let r = '82ff40c0a986c6a5cfad4ddf4c3aa6996f1a7837f9c398e17e5de5cbd5a12b28'
    let hash = SecUtil.keccak256(msg)
    assert.equal(hash.toString('hex'), r)
  })
})

describe('keccak without hexprefix', function () {
  it('should produce a hash', function () {
    let msg = '3c9229289a6125f7fdf1885a77bb12c37a8d3b4962d936f7e3084dece32a3ca1'
    let r = '22ae1937ff93ec72c4d46ff3e854661e3363440acd6f6e4adf8f1a8978382251'
    let hash = SecUtil.keccak(msg)
    assert.equal(hash.toString('hex'), r)
  })
})

describe('keccak-512', function () {
  it('should produce a hash', function () {
    let msg = '0x3c9229289a6125f7fdf1885a77bb12c37a8d3b4962d936f7e3084dece32a3ca1'
    let r = '36fdacd0339307068e9ed191773a6f11f6f9f99016bd50f87fd529ab7c87e1385f2b7ef1ac257cc78a12dcb3e5804254c6a7b404a6484966b831eadc721c3d24'
    let hash = SecUtil.keccak(msg, 512)
    assert.equal(hash.toString('hex'), r)
  })
})

describe('sha256', function () {
  it('should produce a sha256', function () {
    let msg = '0x3c9229289a6125f7fdf1885a77bb12c37a8d3b4962d936f7e3084dece32a3ca1'
    let r = '58bbda5e10bc11a32d808e40f9da2161a64f00b5557762a161626afe19137445'
    let hash = SecUtil.sha256(msg)
    assert.equal(hash.toString('hex'), r)
  })
})

describe('ripemd160', function () {
  it('should produce a ripemd160', function () {
    let msg = '0x3c9229289a6125f7fdf1885a77bb12c37a8d3b4962d936f7e3084dece32a3ca1'
    let r = '4bb0246cbfdfddbe605a374f1187204c896fabfd'
    let hash = SecUtil.ripemd160(msg)
    assert.equal(hash.toString('hex'), r)
  })

  it('should produce a padded ripemd160', function () {
    let msg = '0x3c9229289a6125f7fdf1885a77bb12c37a8d3b4962d936f7e3084dece32a3ca1'
    let r = '0000000000000000000000004bb0246cbfdfddbe605a374f1187204c896fabfd'
    let hash = SecUtil.ripemd160(msg, true)
    assert.equal(hash.toString('hex'), r)
  })
})

describe('rlphash', function () {
  it('should produce a keccak-256 hash of the rlp data', function () {
    let msg = '0x3c9229289a6125f7fdf1885a77bb12c37a8d3b4962d936f7e3084dece32a3ca1'
    let r = '33f491f24abdbdbf175e812b94e7ede338d1c7f01efb68574acd279a15a39cbe'
    let hash = SecUtil.rlphash(msg)
    assert.equal(hash.toString('hex'), r)
  })
})

describe('unpad', function () {
  it('should unpad a string', function () {
    let str = '0000000006600'
    let r = SecUtil.unpad(str)
    assert.equal(r, '6600')
  })
})

describe('unpad a hex string', function () {
  it('should unpad a string', function () {
    let str = '0x0000000006600'
    let r = SecUtil.unpad(str)
    assert.equal(r, '6600')
  })
})

describe('pad', function () {
  it('should left pad a Buffer', function () {
    let buf = Buffer.from([9, 9])
    let padded = SecUtil.setLength(buf, 3)
    assert.equal(padded.toString('hex'), '000909')
  })
  it('should left truncate a Buffer', function () {
    let buf = Buffer.from([9, 0, 9])
    let padded = SecUtil.setLength(buf, 2)
    assert.equal(padded.toString('hex'), '0009')
  })
  it('should left pad a Buffer - alias', function () {
    let buf = Buffer.from([9, 9])
    let padded = SecUtil.setLengthLeft(buf, 3)
    assert.equal(padded.toString('hex'), '000909')
  })
})

describe('rpad', function () {
  it('should right pad a Buffer', function () {
    let buf = Buffer.from([9, 9])
    let padded = SecUtil.setLength(buf, 3, true)
    assert.equal(padded.toString('hex'), '090900')
  })
  it('should right truncate a Buffer', function () {
    let buf = Buffer.from([9, 0, 9])
    let padded = SecUtil.setLength(buf, 2, true)
    assert.equal(padded.toString('hex'), '0900')
  })
  it('should right pad a Buffer - alias', function () {
    let buf = Buffer.from([9, 9])
    let padded = SecUtil.setLengthRight(buf, 3)
    assert.equal(padded.toString('hex'), '090900')
  })
})

describe('bufferToHex', function () {
  it('should convert a buffer to hex', function () {
    let buf = Buffer.from('5b9ac8', 'hex')
    let hex = SecUtil.bufferToHex(buf)
    assert.equal(hex, '0x5b9ac8')
  })
  it('empty buffer', function () {
    let buf = Buffer.alloc(0)
    let hex = SecUtil.bufferToHex(buf)
    assert.strictEqual(hex, '0x')
  })
})

describe('intToHex', function () {
  it('should convert a int to hex', function () {
    let i = 6003400
    let hex = SecUtil.intToHex(i)
    assert.equal(hex, '0x5b9ac8')
  })
})

describe('intToBuffer', function () {
  it('should convert a int to a buffer', function () {
    let i = 6003400
    let buf = SecUtil.intToBuffer(i)
    assert.equal(buf.toString('hex'), '5b9ac8')
  })
})

describe('bufferToInt', function () {
  it('should convert a int to hex', function () {
    let buf = Buffer.from('5b9ac8', 'hex')
    let i = SecUtil.bufferToInt(buf)
    assert.equal(i, 6003400)
    assert.equal(SecUtil.bufferToInt(Buffer.allocUnsafe(0)), 0)
  })
  it('should convert empty input to 0', function () {
    assert.equal(SecUtil.bufferToInt(Buffer.allocUnsafe(0)), 0)
  })
})

describe('fromSigned', function () {
  it('should convert an unsigned (negative) buffer to a singed number', function () {
    let neg = '-452312848583266388373324160190187140051835877600158453279131187530910662656'
    let buf = Buffer.allocUnsafe(32).fill(0)
    buf[0] = 255

    assert.equal(SecUtil.fromSigned(buf), neg)
  })
  it('should convert an unsigned (positive) buffer to a singed number', function () {
    let neg = '452312848583266388373324160190187140051835877600158453279131187530910662656'
    let buf = Buffer.allocUnsafe(32).fill(0)
    buf[0] = 1

    assert.equal(SecUtil.fromSigned(buf), neg)
  })
})

describe('toUnsigned', function () {
  it('should convert a signed (negative) number to unsigned', function () {
    let neg = '-452312848583266388373324160190187140051835877600158453279131187530910662656'
    let hex = 'ff00000000000000000000000000000000000000000000000000000000000000'
    let num = new BN(neg)

    assert.equal(SecUtil.toUnsigned(num).toString('hex'), hex)
  })

  it('should convert a signed (positive) number to unsigned', function () {
    let neg = '452312848583266388373324160190187140051835877600158453279131187530910662656'
    let hex = '0100000000000000000000000000000000000000000000000000000000000000'
    let num = new BN(neg)

    assert.equal(SecUtil.toUnsigned(num).toString('hex'), hex)
  })
})

describe('isValidPrivate', function () {
  let SECP256K1_N = new BN('fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141', 16)
  it('should fail on short input', function () {
    let tmp = '0011223344'
    assert.equal(SecUtil.isValidPrivate(Buffer.from(tmp, 'hex')), false)
  })
  it('should fail on too big input', function () {
    let tmp = '3a443d8381a6798a70c6ff9304bdc8cb0163c23211d11628fae52ef9e0dca11a001cf066d56a8156fc201cd5df8a36ef694eecd258903fca7086c1fae7441e1d'
    assert.equal(SecUtil.isValidPrivate(Buffer.from(tmp, 'hex')), false)
  })
  it('should fail on invalid curve (zero)', function () {
    let tmp = '0000000000000000000000000000000000000000000000000000000000000000'
    assert.equal(SecUtil.isValidPrivate(Buffer.from(tmp, 'hex')), false)
  })
  it('should fail on invalid curve (== N)', function () {
    let tmp = SECP256K1_N.toString(16)
    assert.equal(SecUtil.isValidPrivate(Buffer.from(tmp, 'hex')), false)
  })
  it('should fail on invalid curve (>= N)', function () {
    let tmp = SECP256K1_N.addn(1).toString(16)
    assert.equal(SecUtil.isValidPrivate(Buffer.from(tmp, 'hex')), false)
  })
  it('should work otherwise (< N)', function () {
    let tmp = SECP256K1_N.subn(1).toString(16)
    assert.equal(SecUtil.isValidPrivate(Buffer.from(tmp, 'hex')), true)
  })
})

describe('isValidPublic', function () {
  it('should fail on too short input', function () {
    let pubKey = '3a443d8381a6798a70c6ff9304bdc8cb0163c23211d11628fae52ef9e0dca11a001cf066d56a8156fc201cd5df8a36ef694eecd258903fca7086c1fae744'
    pubKey = Buffer.from(pubKey, 'hex')
    assert.equal(SecUtil.isValidPublic(pubKey), false)
  })
  it('should fail on too big input', function () {
    let pubKey = '3a443d8381a6798a70c6ff9304bdc8cb0163c23211d11628fae52ef9e0dca11a001cf066d56a8156fc201cd5df8a36ef694eecd258903fca7086c1fae7441e1d00'
    pubKey = Buffer.from(pubKey, 'hex')
    assert.equal(SecUtil.isValidPublic(pubKey), false)
  })
  it('should fail on SEC1 key', function () {
    let pubKey = '043a443d8381a6798a70c6ff9304bdc8cb0163c23211d11628fae52ef9e0dca11a001cf066d56a8156fc201cd5df8a36ef694eecd258903fca7086c1fae7441e1d'
    pubKey = Buffer.from(pubKey, 'hex')
    assert.equal(SecUtil.isValidPublic(pubKey), false)
  })
  it('shouldn\'t fail on SEC1 key with sanitize enabled', function () {
    let pubKey = '043a443d8381a6798a70c6ff9304bdc8cb0163c23211d11628fae52ef9e0dca11a001cf066d56a8156fc201cd5df8a36ef694eecd258903fca7086c1fae7441e1d'
    pubKey = Buffer.from(pubKey, 'hex')
    assert.equal(SecUtil.isValidPublic(pubKey, true), true)
  })
  it('should fail with an invalid SEC1 public key', function () {
    let pubKey = '023a443d8381a6798a70c6ff9304bdc8cb0163c23211d11628fae52ef9e0dca11a001cf066d56a8156fc201cd5df8a36ef694eecd258903fca7086c1fae7441e1d'
    pubKey = Buffer.from(pubKey, 'hex')
    assert.equal(SecUtil.isValidPublic(pubKey, true), false)
  })
  it('should work with compressed keys with sanitize enabled', function () {
    let pubKey = '033a443d8381a6798a70c6ff9304bdc8cb0163c23211d11628fae52ef9e0dca11a'
    pubKey = Buffer.from(pubKey, 'hex')
    assert.equal(SecUtil.isValidPublic(pubKey, true), true)
  })
  it('should work with sanitize enabled', function () {
    let pubKey = '043a443d8381a6798a70c6ff9304bdc8cb0163c23211d11628fae52ef9e0dca11a001cf066d56a8156fc201cd5df8a36ef694eecd258903fca7086c1fae7441e1d'
    pubKey = Buffer.from(pubKey, 'hex')
    assert.equal(SecUtil.isValidPublic(pubKey, true), true)
  })
  it('should work otherwise', function () {
    let pubKey = '3a443d8381a6798a70c6ff9304bdc8cb0163c23211d11628fae52ef9e0dca11a001cf066d56a8156fc201cd5df8a36ef694eecd258903fca7086c1fae7441e1d'
    pubKey = Buffer.from(pubKey, 'hex')
    assert.equal(SecUtil.isValidPublic(pubKey), true)
  })
})

describe('importPublic', function () {
  let pubKey = '3a443d8381a6798a70c6ff9304bdc8cb0163c23211d11628fae52ef9e0dca11a001cf066d56a8156fc201cd5df8a36ef694eecd258903fca7086c1fae7441e1d'
  it('should work with an SEC public key', function () {
    let tmp = '3a443d8381a6798a70c6ff9304bdc8cb0163c23211d11628fae52ef9e0dca11a001cf066d56a8156fc201cd5df8a36ef694eecd258903fca7086c1fae7441e1d'
    assert.equal(SecUtil.importPublic(Buffer.from(tmp, 'hex')).toString('hex'), pubKey)
  })
  it('should work with uncompressed SEC1 keys', function () {
    let tmp = '043a443d8381a6798a70c6ff9304bdc8cb0163c23211d11628fae52ef9e0dca11a001cf066d56a8156fc201cd5df8a36ef694eecd258903fca7086c1fae7441e1d'
    assert.equal(SecUtil.importPublic(Buffer.from(tmp, 'hex')).toString('hex'), pubKey)
  })
  it('should work with compressed SEC1 keys', function () {
    let tmp = '033a443d8381a6798a70c6ff9304bdc8cb0163c23211d11628fae52ef9e0dca11a'
    assert.equal(SecUtil.importPublic(Buffer.from(tmp, 'hex')).toString('hex'), pubKey)
  })
})

describe('publicToAddress', function () {
  it('should produce an address given a public key', function () {
    let pubKey = '3a443d8381a6798a70c6ff9304bdc8cb0163c23211d11628fae52ef9e0dca11a001cf066d56a8156fc201cd5df8a36ef694eecd258903fca7086c1fae7441e1d'
    let address = '2f015c60e0be116b1f0cd534704db9c92118fb6a'
    pubKey = Buffer.from(pubKey, 'hex')
    let r = SecUtil.publicToAddress(pubKey)
    assert.equal(r.toString('hex'), address)
  })
  it('should produce an address given a SEC1 public key', function () {
    let pubKey = '043a443d8381a6798a70c6ff9304bdc8cb0163c23211d11628fae52ef9e0dca11a001cf066d56a8156fc201cd5df8a36ef694eecd258903fca7086c1fae7441e1d'
    let address = '2f015c60e0be116b1f0cd534704db9c92118fb6a'
    pubKey = Buffer.from(pubKey, 'hex')
    let r = SecUtil.publicToAddress(pubKey, true)
    assert.equal(r.toString('hex'), address)
  })
  it('shouldn\'t produce an address given an invalid SEC1 public key', function () {
    let pubKey = '023a443d8381a6798a70c6ff9304bdc8cb0163c23211d11628fae52ef9e0dca11a001cf066d56a8156fc201cd5df8a36ef694eecd258903fca7086c1fae7441e1d'
    pubKey = Buffer.from(pubKey, 'hex')
    assert.throws(function () {
      SecUtil.publicToAddress(pubKey, true)
    })
  })
  it('shouldn\'t produce an address given an invalid public key', function () {
    let pubKey = '3a443d8381a6798a70c6ff9304bdc8cb0163c23211d11628fae52ef9e0dca11a001cf066d56a8156fc201cd5df8a36ef694eecd258903fca7086c1fae744'
    pubKey = Buffer.from(pubKey, 'hex')
    assert.throws(function () {
      SecUtil.publicToAddress(pubKey)
    })
  })
})

describe('publicToAddress 0x', function () {
  it('should produce an address given a public key', function () {
    let pubKey = '0x3a443d8381a6798a70c6ff9304bdc8cb0163c23211d11628fae52ef9e0dca11a001cf066d56a8156fc201cd5df8a36ef694eecd258903fca7086c1fae7441e1d'
    let address = '2f015c60e0be116b1f0cd534704db9c92118fb6a'
    let r = SecUtil.publicToAddress(pubKey)
    assert.equal(r.toString('hex'), address)
  })
})

describe('privateToPublic', function () {
  it('should produce a public key given a private key', function () {
    let pubKey = '3a443d8381a6798a70c6ff9304bdc8cb0163c23211d11628fae52ef9e0dca11a001cf066d56a8156fc201cd5df8a36ef694eecd258903fca7086c1fae7441e1d'
    let privateKey = Buffer.from([234, 84, 189, 197, 45, 22, 63, 136, 201, 58, 176, 97, 87, 130, 207, 113, 138, 46, 251, 158, 81, 167, 152, 154, 171, 27, 8, 6, 126, 156, 28, 95])
    let r = SecUtil.privateToPublic(privateKey).toString('hex')
    assert.equal(r.toString('hex'), pubKey)
  })
  it('shouldn\'t produce a public key given an invalid private key', function () {
    let privateKey1 = Buffer.from([234, 84, 189, 197, 45, 22, 63, 136, 201, 58, 176, 97, 87, 130, 207, 113, 138, 46, 251, 158, 81, 167, 152, 154, 171, 27, 8, 6, 126, 156, 28, 95, 42])
    let privateKey2 = Buffer.from([234, 84, 189, 197, 45, 22, 63, 136, 201, 58, 176, 97, 87, 130, 207, 113, 138, 46, 251, 158, 81, 167, 152, 154, 171, 27, 8, 6, 126, 156, 28])
    assert.throws(function () {
      SecUtil.privateToPublic(privateKey1)
    })
    assert.throws(function () {
      SecUtil.privateToPublic(privateKey2)
    })
  })
})

describe('privateToAddress', function () {
  it('should produce an address given a private key', function () {
    let address = '2f015c60e0be116b1f0cd534704db9c92118fb6a'
    // Our private key
    let privateKey = Buffer.from([234, 84, 189, 197, 45, 22, 63, 136, 201, 58, 176, 97, 87, 130, 207, 113, 138, 46, 251, 158, 81, 167, 152, 154, 171, 27, 8, 6, 126, 156, 28, 95])
    let r = SecUtil.privateToAddress(privateKey).toString('hex')
    assert.equal(r.toString('hex'), address)
  })
})

describe('generateContractAddress', function () {
  it('should produce an address given a public key', function () {
    let add = SecUtil.generateContractAddress('990ccf8a0de58091c028d6ff76bb235ee67c1c39', 14).toString('hex')
    assert.equal(add.toString('hex'), '936a4295d8d74e310c0c95f0a63e53737b998d12')
  })
})

describe('generateContractAddress with hex prefix', function () {
  it('should produce an address given a public key', function () {
    let add = SecUtil.generateContractAddress('0x990ccf8a0de58091c028d6ff76bb235ee67c1c39', 14).toString('hex')
    assert.equal(add.toString('hex'), 'd658a4b8247c14868f3c512fa5cbb6e458e4a989')
  })
})

describe('generateContractAddress with nonce 0 (special case)', function () {
  it('should produce an address given a public key', function () {
    let add = SecUtil.generateContractAddress('0x990ccf8a0de58091c028d6ff76bb235ee67c1c39', 0).toString('hex')
    assert.equal(add.toString('hex'), 'bfa69ba91385206bfdd2d8b9c1a5d6c10097a85b')
  })
})

describe('hex prefix', function () {
  let string = 'd658a4b8247c14868f3c512fa5cbb6e458e4a989'
  it('should add', function () {
    assert.equal(SecUtil.addHexPrefix(string), '0x' + string)
  })
  it('should return on non-string input', function () {
    assert.equal(SecUtil.addHexPrefix(1), 1)
  })
})

describe('isPrecompiled', function () {
  it('should return true', function () {
    assert.equal(SecUtil.isPrecompiled('0000000000000000000000000000000000000001'), true)
    assert.equal(SecUtil.isPrecompiled('0000000000000000000000000000000000000002'), true)
    assert.equal(SecUtil.isPrecompiled('0000000000000000000000000000000000000003'), true)
    assert.equal(SecUtil.isPrecompiled('0000000000000000000000000000000000000004'), true)
    assert.equal(SecUtil.isPrecompiled('0000000000000000000000000000000000000005'), true)
    assert.equal(SecUtil.isPrecompiled('0000000000000000000000000000000000000006'), true)
    assert.equal(SecUtil.isPrecompiled('0000000000000000000000000000000000000007'), true)
    assert.equal(SecUtil.isPrecompiled('0000000000000000000000000000000000000008'), true)
    assert.equal(SecUtil.isPrecompiled(Buffer.from('0000000000000000000000000000000000000001', 'hex')), true)
  })
  it('should return false', function () {
    assert.equal(SecUtil.isPrecompiled('0000000000000000000000000000000000000000'), false)
    assert.equal(SecUtil.isPrecompiled('0000000000000000000000000000000000000009'), false)
    assert.equal(SecUtil.isPrecompiled('1000000000000000000000000000000000000000'), false)
    assert.equal(SecUtil.isPrecompiled(Buffer.from('0000000000000000000000000000000000000000', 'hex')), false)
  })
})

describe('toBuffer', function () {
  it('should work', function () {
    // Buffer
    assert.deepEqual(SecUtil.toBuffer(Buffer.allocUnsafe(0)), Buffer.allocUnsafe(0))
    // Array
    assert.deepEqual(SecUtil.toBuffer([]), Buffer.allocUnsafe(0))
    // String
    assert.deepEqual(SecUtil.toBuffer('11'), Buffer.from([49, 49]))
    assert.deepEqual(SecUtil.toBuffer('0x11'), Buffer.from([17]))
    assert.deepEqual(SecUtil.toBuffer('1234').toString('hex'), '31323334')
    assert.deepEqual(SecUtil.toBuffer('0x1234').toString('hex'), '1234')
    // Number
    assert.deepEqual(SecUtil.toBuffer(1), Buffer.from([1]))
    // null
    assert.deepEqual(SecUtil.toBuffer(null), Buffer.allocUnsafe(0))
    // undefined
    assert.deepEqual(SecUtil.toBuffer(), Buffer.allocUnsafe(0))
    // 'toBN'
    assert.deepEqual(SecUtil.toBuffer(new BN(1)), Buffer.from([1]))
    // 'toArray'
    assert.deepEqual(SecUtil.toBuffer({ toArray: function () { return [1] } }), Buffer.from([1]))
  })
  it('should fail', function () {
    assert.throws(function () {
      SecUtil.toBuffer({ test: 1 })
    })
  })
})

describe('baToJSON', function () {
  it('should turn a array of buffers into a pure json object', function () {
    let ba = [Buffer.from([0]), Buffer.from([1]), [Buffer.from([2])]]
    assert.deepEqual(SecUtil.baToJSON(ba), ['0x00', '0x01', ['0x02']])
  })
  it('should turn a buffers into string', function () {
    assert.deepEqual(SecUtil.baToJSON(Buffer.from([0])), '0x00')
  })
})

let echash = Buffer.from('82ff40c0a986c6a5cfad4ddf4c3aa6996f1a7837f9c398e17e5de5cbd5a12b28', 'hex')
let ecprivkey = Buffer.from('3c9229289a6125f7fdf1885a77bb12c37a8d3b4962d936f7e3084dece32a3ca1', 'hex')

describe('ecsign', function () {
  it('should produce a signature', function () {
    let sig = SecUtil.ecsign(echash, ecprivkey)
    assert.deepEqual(sig.r, Buffer.from('99e71a99cb2270b8cac5254f9e99b6210c6c10224a1579cf389ef88b20a1abe9', 'hex'))
    assert.deepEqual(sig.s, Buffer.from('129ff05af364204442bdb53ab6f18a99ab48acc9326fa689f228040429e3ca66', 'hex'))
    assert.equal(sig.v, 27)
  })
})

describe('ecrecover', function () {
  it('should recover a public key', function () {
    let r = Buffer.from('99e71a99cb2270b8cac5254f9e99b6210c6c10224a1579cf389ef88b20a1abe9', 'hex')
    let s = Buffer.from('129ff05af364204442bdb53ab6f18a99ab48acc9326fa689f228040429e3ca66', 'hex')
    let pubkey = SecUtil.ecrecover(echash, 27, r, s)
    assert.deepEqual(pubkey, SecUtil.privateToPublic(ecprivkey))
  })
  it('should fail on an invalid signature (v = 21)', function () {
    let r = Buffer.from('99e71a99cb2270b8cac5254f9e99b6210c6c10224a1579cf389ef88b20a1abe9', 'hex')
    let s = Buffer.from('129ff05af364204442bdb53ab6f18a99ab48acc9326fa689f228040429e3ca66', 'hex')
    assert.throws(function () {
      SecUtil.ecrecover(echash, 21, r, s)
    })
  })
  it('should fail on an invalid signature (v = 29)', function () {
    let r = Buffer.from('99e71a99cb2270b8cac5254f9e99b6210c6c10224a1579cf389ef88b20a1abe9', 'hex')
    let s = Buffer.from('129ff05af364204442bdb53ab6f18a99ab48acc9326fa689f228040429e3ca66', 'hex')
    assert.throws(function () {
      SecUtil.ecrecover(echash, 29, r, s)
    })
  })
  it('should fail on an invalid signature (swapped points)', function () {
    let r = Buffer.from('99e71a99cb2270b8cac5254f9e99b6210c6c10224a1579cf389ef88b20a1abe9', 'hex')
    let s = Buffer.from('129ff05af364204442bdb53ab6f18a99ab48acc9326fa689f228040429e3ca66', 'hex')
    assert.throws(function () {
      SecUtil.ecrecover(echash, 27, s, r)
    })
  })
})

describe('hashPersonalMessage', function () {
  it('should produce a deterministic hash', function () {
    let h = SecUtil.hashPersonalMessage(Buffer.from('Hello world'))
    assert.deepEqual(h, Buffer.from('342cd2a0b4d633e62b0e9d318ce9d55c23de73570a44ab7adf7a1b8fa61c6ff7', 'hex'))
  })
})

describe('isValidSignature', function () {
  it('should fail on an invalid signature (shorter r))', function () {
    let r = Buffer.from('99e71a99cb2270b8cac5254f9e99b6210c6c10224a1579cf389ef88b20a1ab', 'hex')
    let s = Buffer.from('129ff05af364204442bdb53ab6f18a99ab48acc9326fa689f228040429e3ca66', 'hex')
    assert.equal(SecUtil.isValidSignature(27, r, s), false)
  })
  it('should fail on an invalid signature (shorter s))', function () {
    let r = Buffer.from('99e71a99cb2270b8cac5254f9e99b6210c6c10224a1579cf389ef88b20a1abe9', 'hex')
    let s = Buffer.from('129ff05af364204442bdb53ab6f18a99ab48acc9326fa689f228040429e3ca', 'hex')
    assert.equal(SecUtil.isValidSignature(27, r, s), false)
  })
  it('should fail on an invalid signature (v = 21)', function () {
    let r = Buffer.from('99e71a99cb2270b8cac5254f9e99b6210c6c10224a1579cf389ef88b20a1abe9', 'hex')
    let s = Buffer.from('129ff05af364204442bdb53ab6f18a99ab48acc9326fa689f228040429e3ca66', 'hex')
    assert.equal(SecUtil.isValidSignature(21, r, s), false)
  })
  it('should fail on an invalid signature (v = 29)', function () {
    let r = Buffer.from('99e71a99cb2270b8cac5254f9e99b6210c6c10224a1579cf389ef88b20a1abe9', 'hex')
    let s = Buffer.from('129ff05af364204442bdb53ab6f18a99ab48acc9326fa689f228040429e3ca66', 'hex')
    assert.equal(SecUtil.isValidSignature(29, r, s), false)
  })
  it('should work otherwise', function () {
    let r = Buffer.from('99e71a99cb2270b8cac5254f9e99b6210c6c10224a1579cf389ef88b20a1abe9', 'hex')
    let s = Buffer.from('129ff05af364204442bdb53ab6f18a99ab48acc9326fa689f228040429e3ca66', 'hex')
    assert.equal(SecUtil.isValidSignature(27, r, s), true)
  })
  // FIXME: add homestead test
})

let checksumAddresses = [
  // All caps
  '0x52908400098527886E0F7030069857D2E4169EE7',
  '0x8617E340B3D01FA5F11F306F4090FD50E238070D',
  // All Lower
  '0xde709f2102306220921060314715629080e2fb77',
  '0x27b1fdb04752bbc536007a920d24acb045561c26',
  // Normal
  '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed',
  '0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359',
  '0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB',
  '0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb'
]

describe('toChecksumAddress', function () {
  it('should work', function () {
    for (let i = 0; i < checksumAddresses.length; i++) {
      let tmp = checksumAddresses[i]
      assert.equal(SecUtil.toChecksumAddress(tmp.toLowerCase()), tmp)
    }
  })
})

describe('isValidChecksumAddress', function () {
  it('should return true', function () {
    for (let i = 0; i < checksumAddresses.length; i++) {
      assert.equal(SecUtil.isValidChecksumAddress(checksumAddresses[i]), true)
    }
  })
  it('should validate', function () {
    assert.equal(SecUtil.isValidChecksumAddress('0x2f015c60e0be116b1f0cd534704db9c92118fb6a'), false)
  })
})

describe('isValidAddress', function () {
  it('should return true', function () {
    assert.equal(SecUtil.isValidAddress('0x2f015c60e0be116b1f0cd534704db9c92118fb6a'), true)
    assert.equal(SecUtil.isValidAddress('0x52908400098527886E0F7030069857D2E4169EE7'), true)
  })
  it('should return false', function () {
    assert.equal(SecUtil.isValidAddress('2f015c60e0be116b1f0cd534704db9c92118fb6a'), false)
    assert.equal(SecUtil.isValidAddress('0x2f015c60e0be116b1f0cd534704db9c92118fb6'), false)
    assert.equal(SecUtil.isValidAddress('0x2f015c60e0be116b1f0cd534704db9c92118fb6aa'), false)
    assert.equal(SecUtil.isValidAddress('0X52908400098527886E0F7030069857D2E4169EE7'), false)
    assert.equal(SecUtil.isValidAddress('x2f015c60e0be116b1f0cd534704db9c92118fb6a'), false)
  })
})

describe('message sig', function () {
  const r = Buffer.from('99e71a99cb2270b8cac5254f9e99b6210c6c10224a1579cf389ef88b20a1abe9', 'hex')
  const s = Buffer.from('129ff05af364204442bdb53ab6f18a99ab48acc9326fa689f228040429e3ca66', 'hex')

  it('should return hex strings that the RPC can use', function () {
    assert.equal(SecUtil.toRpcSig(27, r, s), '0x99e71a99cb2270b8cac5254f9e99b6210c6c10224a1579cf389ef88b20a1abe9129ff05af364204442bdb53ab6f18a99ab48acc9326fa689f228040429e3ca6600')
    assert.deepEqual(SecUtil.fromRpcSig('0x99e71a99cb2270b8cac5254f9e99b6210c6c10224a1579cf389ef88b20a1abe9129ff05af364204442bdb53ab6f18a99ab48acc9326fa689f228040429e3ca6600'), {
      v: 27,
      r: r,
      s: s
    })
  })

  it('should throw on invalid length', function () {
    assert.throws(function () {
      SecUtil.fromRpcSig('')
    })
    assert.throws(function () {
      SecUtil.fromRpcSig('0x99e71a99cb2270b8cac5254f9e99b6210c6c10224a1579cf389ef88b20a1abe9129ff05af364204442bdb53ab6f18a99ab48acc9326fa689f228040429e3ca660042')
    })
  })

  it('pad short r and s values', function () {
    assert.equal(SecUtil.toRpcSig(27, r.slice(20), s.slice(20)), '0x00000000000000000000000000000000000000004a1579cf389ef88b20a1abe90000000000000000000000000000000000000000326fa689f228040429e3ca6600')
  })

  it('should throw on invalid v value', function () {
    assert.throws(function () {
      SecUtil.toRpcSig(1, r, s)
    })
  })
})

describe('stripHexPrefix', function () {
  it('should stripHexPrefix strip prefix of valid strings', () => {
    assert.equal(SecUtil.stripHexPrefix('0xkdsfksfdkj'), 'kdsfksfdkj')
    assert.equal(SecUtil.stripHexPrefix('0xksfdkj'), 'ksfdkj')
    assert.equal(SecUtil.stripHexPrefix('0xkdsfdkj'), 'kdsfdkj')
    assert.equal(SecUtil.stripHexPrefix('0x23442sfdkj'), '23442sfdkj')
    assert.equal(SecUtil.stripHexPrefix('0xkdssdfssfdkj'), 'kdssdfssfdkj')
    assert.equal(SecUtil.stripHexPrefix('0xaaaasfdkj'), 'aaaasfdkj')
    assert.equal(SecUtil.stripHexPrefix('0xkdsdfsfsdfsdfsdfdkj'), 'kdsdfsfsdfsdfsdfdkj')
    assert.equal(SecUtil.stripHexPrefix('0x111dssdddj'), '111dssdddj')
  })

  it('should stripHexPrefix strip prefix of mix hexed strings', () => {
    assert.equal(SecUtil.stripHexPrefix('0xkdsfksfdkj'), 'kdsfksfdkj')
    assert.equal(SecUtil.stripHexPrefix('ksfdkj'), 'ksfdkj')
    assert.equal(SecUtil.stripHexPrefix('kdsfdkj'), 'kdsfdkj')
    assert.equal(SecUtil.stripHexPrefix('23442sfdkj'), '23442sfdkj')
    assert.equal(SecUtil.stripHexPrefix('0xkdssdfssfdkj'), 'kdssdfssfdkj')
    assert.equal(SecUtil.stripHexPrefix('aaaasfdkj'), 'aaaasfdkj')
    assert.equal(SecUtil.stripHexPrefix('kdsdfsfsdfsdfsdfdkj'), 'kdsdfsfsdfsdfsdfdkj')
    assert.equal(SecUtil.stripHexPrefix('111dssdddj'), '111dssdddj')
  })

  it('should stripHexPrefix bypass if not string', () => {
    assert.equal(SecUtil.stripHexPrefix(null), null)
    assert.equal(SecUtil.stripHexPrefix(undefined), undefined)
    assert.equal(SecUtil.stripHexPrefix(242423), 242423)
    assert.deepEqual(SecUtil.stripHexPrefix({}), {})
    assert.deepEqual(SecUtil.stripHexPrefix([]), [])
    assert.equal(SecUtil.stripHexPrefix(true), true)
  })
})

describe('padToEven', function () {
  it('valid padToEven should pad to even', () => {
    assert.equal(String(SecUtil.padToEven('0')).length % 2, 0)
    assert.equal(String(SecUtil.padToEven('111')).length % 2, 0)
    assert.equal(String(SecUtil.padToEven('22222')).length % 2, 0)
    assert.equal(String(SecUtil.padToEven('ddd')).length % 2, 0)
    assert.equal(String(SecUtil.padToEven('aa')).length % 2, 0)
    assert.equal(String(SecUtil.padToEven('aaaaaa')).length % 2, 0)
    assert.equal(String(SecUtil.padToEven('sdssd')).length % 2, 0)
    assert.equal(String(SecUtil.padToEven('eee')).length % 2, 0)
    assert.equal(String(SecUtil.padToEven('w')).length % 2, 0)
  })

  it('valid padToEven should pad to even check string prefix 0', () => {
    assert.equal(String(SecUtil.padToEven('0')), '00')
    assert.equal(String(SecUtil.padToEven('111')), '0111')
    assert.equal(String(SecUtil.padToEven('22222')), '022222')
    assert.equal(String(SecUtil.padToEven('ddd')), '0ddd')
    assert.equal(String(SecUtil.padToEven('aa')), 'aa')
    assert.equal(String(SecUtil.padToEven('aaaaaa')), 'aaaaaa')
    assert.equal(String(SecUtil.padToEven('sdssd')), '0sdssd')
    assert.equal(String(SecUtil.padToEven('eee')), '0eee')
    assert.equal(String(SecUtil.padToEven('w')), '0w')
  })

  it('should padToEven throw as expected string got null', () => {
    try {
      SecUtil.padToEven(null)
    } catch (error) {
      assert.equal(typeof error, 'object')
    }
  })

  it('should padToEven throw as expected string got undefined', () => {
    try {
      SecUtil.padToEven(undefined)
    } catch (error) {
      assert.equal(typeof error, 'object')
    }
  })

  it('should padToEven throw as expected string got {}', () => {
    try {
      SecUtil.padToEven({})
    } catch (error) {
      assert.equal(typeof error, 'object')
    }
  })

  it('should padToEven throw as expected string got new Buffer()', () => {
    try {
      SecUtil.padToEven(new Buffer())
    } catch (error) {
      assert.equal(typeof error, 'object')
    }
  })

  it('should padToEven throw as expected string got number', () => {
    try {
      SecUtil.padToEven(24423232)
    } catch (error) {
      assert.equal(typeof error, 'object')
    }
  })
})

describe('getKeys', function () {
  it('method getKeys should throw as expected array for params got number', () => {
    try {
      SecUtil.getKeys(2482822)
    } catch (error) {
      assert.equal(typeof error, 'object')
    }
  })

  it('method invalid getKeys with allow empty and no defined value', () => {
    try {
      SecUtil.getKeys([{ type: undefined }], 'type', true)
    } catch (error) {
      assert.equal(typeof error, 'object')
    }
  })

  it('method valid getKeys with allow empty and false', () => {
    try {
      SecUtil.getKeys([{ type: true }], 'type', true)
    } catch (error) {
      assert.equal(typeof error, 'object')
    }
  })

  it('method getKeys should throw as expected array for params got number', () => {
    try {
      SecUtil.getKeys(2482822, 293849824)
    } catch (error) {
      assert.equal(typeof error, 'object')
    }
  })

  it('method getKeys should throw as expected array for params got object', () => {
    try {
      SecUtil.getKeys({}, [])
    } catch (error) {
      assert.equal(typeof error, 'object')
    }
  })

  it('method getKeys should throw as expected array for params got null', () => {
    try {
      SecUtil.getKeys(null)
    } catch (error) {
      assert.equal(typeof error, 'object')
    }
  })

  it('method getKeys should throw as expected array for params got false', () => {
    try {
      SecUtil.getKeys(false)
    } catch (error) {
      assert.equal(typeof error, 'object')
    }
  })

  it('valid getKeys should get keys from object in array', () => {
    assert.deepEqual(SecUtil.getKeys([{ type: 'sfd' }, { type: 'something' }], 'type'), ['sfd', 'something'])
    assert.deepEqual(SecUtil.getKeys([{ cool: 'something' }, { cool: 'fdsdfsfd' }], 'cool'), ['something', 'fdsdfsfd'])
    assert.deepEqual(SecUtil.getKeys([{ type: '234424' }, { type: '243234242432' }], 'type'), ['234424', '243234242432'])
    assert.deepEqual(SecUtil.getKeys([{ type: 'something' }, { type: 'something' }], 'type'), ['something', 'something'])
    assert.deepEqual(SecUtil.getKeys([{ type: 'something' }], 'type'), ['something'])
    assert.deepEqual(SecUtil.getKeys([], 'type'), [])
    assert.deepEqual(SecUtil.getKeys([{ type: 'something' }, { type: 'something' }, { type: 'something' }], 'type'), ['something', 'something', 'something'])
  })
})

describe('isHexString', function () {
  it('valid isHexString tests', () => {
    assert.equal(SecUtil.isHexString('0x0e026d45820d91356fc73d7ff2bdef353ebfe7e9'), true)
    assert.equal(SecUtil.isHexString('0x1e026d45820d91356fc73d7ff2bdef353ebfe7e9'), true)
    assert.equal(SecUtil.isHexString('0x6e026d45820d91356fc73d7ff2bdef353ebfe7e9'), true)
    assert.equal(SecUtil.isHexString('0xecfaa1a0c4372a2ac5cca1e164510ec8df04f681fc960797f1419802ec00b225'), true)
    assert.equal(SecUtil.isHexString('0x6e0e6d45820d91356fc73d7ff2bdef353ebfe7e9'), true)
    assert.equal(SecUtil.isHexString('0x620e6d45820d91356fc73d7ff2bdef353ebfe7e9'), true)
    assert.equal(SecUtil.isHexString('0x1e0e6d45820d91356fc73d7ff2bdef353ebfe7e9'), true)
    assert.equal(SecUtil.isHexString('0x2e0e6d45820d91356fc73d7ff2bdef353ebfe7e9'), true)
    assert.equal(SecUtil.isHexString('0x220c96d48733a847570c2f0b40daa8793b3ae875b26a4ead1f0f9cead05c3863'), true)
    assert.equal(SecUtil.isHexString('0x2bb303f0ae65c64ef80a3bb3ee8ceef5d50065bd'), true)
    assert.equal(SecUtil.isHexString('0x6e026d45820d91256fc73d7ff2bdef353ebfe7e9'), true)
  })

  it('invalid isHexString tests', () => {
    assert.equal(SecUtil.isHexString(' 0x0e026d45820d91356fc73d7ff2bdef353ebfe7e9'), false)
    assert.equal(SecUtil.isHexString('fdsjfsd'), false)
    assert.equal(SecUtil.isHexString(' 0xfdsjfsd'), false)
    assert.equal(SecUtil.isHexString('0xfds*jfsd'), false)
    assert.equal(SecUtil.isHexString('0xfds$jfsd'), false)
    assert.equal(SecUtil.isHexString('0xf@dsjfsd'), false)
    assert.equal(SecUtil.isHexString('0xfdsjf!sd'), false)
    assert.equal(SecUtil.isHexString('fds@@jfsd'), false)
    assert.equal(SecUtil.isHexString(24223), false)
    assert.equal(SecUtil.isHexString(null), false)
    assert.equal(SecUtil.isHexString(undefined), false)
    assert.equal(SecUtil.isHexString(false), false)
    assert.equal(SecUtil.isHexString({}), false)
    assert.equal(SecUtil.isHexString([]), false)
  })
})

describe('getBinarySize', function () {
  it('valid getBinarySize should get binary size of string', () => {
    assert.equal(SecUtil.getBinarySize('0x0e026d45820d91356fc73d7ff2bdef353ebfe7e9'), 42)
    assert.equal(SecUtil.getBinarySize('0x220c96d48733a847570c2f0b40daa8793b3ae875b26a4ead1f0f9cead05c3863'), 66)
  })

  it('invalid getBinarySize should throw invalid type Boolean', () => {
    try {
      SecUtil.getBinarySize(false)
    } catch (error) {
      assert.equal(typeof error, 'object')
    }
  })

  it('invalid getBinarySize should throw invalid type object', () => {
    try {
      SecUtil.getBinarySize({})
    } catch (error) {
      assert.equal(typeof error, 'object')
    }
  })

  it('invalid getBinarySize should throw invalid type Array', () => {
    try {
      SecUtil.getBinarySize([])
    } catch (error) {
      assert.equal(typeof error, 'object')
    }
  })
})

describe('arrayContainsArray', function () {
  it('valid arrayContainsArray should array contain every array', () => {
    assert.equal(SecUtil.arrayContainsArray([1, 2, 3], [1, 2]), true)
    assert.equal(SecUtil.arrayContainsArray([3, 3], [3, 3]), true)
    assert.equal(SecUtil.arrayContainsArray([1, 2, 'h'], [1, 2, 'h']), true)
    assert.equal(SecUtil.arrayContainsArray([1, 2, 'fsffds'], [1, 2, 'fsffds']), true)
    assert.equal(SecUtil.arrayContainsArray([1], [1]), true)
    assert.equal(SecUtil.arrayContainsArray([], []), true)
    assert.equal(SecUtil.arrayContainsArray([1, 3333], [1, 3333]), true)
  })
  it('valid arrayContainsArray should array some every array', () => {
    assert.equal(SecUtil.arrayContainsArray([1, 2], [1], true), true)
    assert.equal(SecUtil.arrayContainsArray([3, 3], [3, 2323], true), true)
    assert.equal(SecUtil.arrayContainsArray([1, 2, 'h'], [2332, 2, 'h'], true), true)
    assert.equal(SecUtil.arrayContainsArray([1, 2, 'fsffds'], [3232, 2, 'fsffds'], true), true)
    assert.equal(SecUtil.arrayContainsArray([1], [1], true), true)
    assert.equal(SecUtil.arrayContainsArray([1, 3333], [1, 323232], true), true)
  })

  it('method arrayContainsArray should throw as expected array for params got false', () => {
    try {
      SecUtil.arrayContainsArray(false)
    } catch (error) {
      assert.equal(typeof error, 'object')
    }
  })

  it('method arrayContainsArray should throw as expected array for params got false', () => {
    try {
      SecUtil.arrayContainsArray([], false)
    } catch (error) {
      assert.equal(typeof error, 'object')
    }
  })

  it('method arrayContainsArray should throw as expected array for params got {}', () => {
    try {
      SecUtil.arrayContainsArray({}, false)
    } catch (error) {
      assert.equal(typeof error, 'object')
    }
  })
})

const fromAsciiTests = [
  { value: 'myString', expected: '0x6d79537472696e67' },
  { value: 'myString\x00', expected: '0x6d79537472696e6700' },
  {
    value: '\u0003\u0000\u0000\u00005èÆÕL]\u0012|Î¾\u001a7«\u00052\u0011(ÐY\n<\u0010\u0000\u0000\u0000\u0000\u0000\u0000e!ßd/ñõì\f:z¦Î¦±ç·÷Í¢Ëß\u00076*\bñùC1ÉUÀé2\u001aÓB',
    expected: '0x0300000035e8c6d54c5d127c9dcebe9e1a37ab9b05321128d097590a3c100000000000006521df642ff1f5ec0c3a7aa6cea6b1e7b7f7cda2cbdf07362a85088e97f19ef94331c955c0e9321ad386428c'
  }
]

describe('fromAscii', () => {
  fromAsciiTests.forEach((test) => {
    it(`should turn ${test.value} to ${test.expected} `, () => {
      assert.strictEqual(SecUtil.fromAscii(test.value), test.expected)
    })
  })
})

const fromUtf8Tests = [
  { value: 'myString', expected: '0x6d79537472696e67' },
  { value: 'myString\x00', expected: '0x6d79537472696e67' },
  { value: 'expected value\u0000\u0000\u0000', expected: '0x65787065637465642076616c7565' }
]

describe('fromUtf8', () => {
  fromUtf8Tests.forEach((test) => {
    it(`should turn ${test.value} to ${test.expected} `, () => {
      assert.strictEqual(SecUtil.fromUtf8(test.value), test.expected)
    })
  })
})

const toUtf8Tests = [
  { value: '0x6d79537472696e67', expected: 'myString' },
  { value: '0x6d79537472696e6700', expected: 'myString' },
  { value: '0x65787065637465642076616c7565000000000000000000000000000000000000', expected: 'expected value' }
]

describe('toUtf8', () => {
  toUtf8Tests.forEach((test) => {
    it(`should turn ${test.value} to ${test.expected} `, () => {
      assert.strictEqual(SecUtil.toUtf8(test.value), test.expected)
    })
  })
})

const toAsciiTests = [
  { value: '0x6d79537472696e67', expected: 'myString' },
  { value: '0x6d79537472696e6700', expected: 'myString\u0000' },
  {
    value: '0x0300000035e8c6d54c5d127c9dcebe9e1a37ab9b05321128d097590a3c100000000000006521df642ff1f5ec0c3a7aa6cea6b1e7b7f7cda2cbdf07362a85088e97f19ef94331c955c0e9321ad386428c',
    expected: '\u0003\u0000\u0000\u00005èÆÕL]\u0012|Î¾\u001a7«\u00052\u0011(ÐY\n<\u0010\u0000\u0000\u0000\u0000\u0000\u0000e!ßd/ñõì\f:z¦Î¦±ç·÷Í¢Ëß\u00076*\bñùC1ÉUÀé2\u001aÓB'
  }
]

describe('toAsciiTests', () => {
  toAsciiTests.forEach((test) => {
    it(`should turn ${test.value} to ${test.expected} `, () => {
      assert.strictEqual(SecUtil.toAscii(test.value), test.expected)
    })
  })
})

describe('intToHex', () => {
  it('should throw when invalid abi', () => {
    assert.throws(() => SecUtil.getKeys([], 3289), Error)
  })
  it('should detect invalid length hex string', () => {
    assert.equal(SecUtil.isHexString('0x0', 2), false)
  })
  it('should convert intToHex', () => {
    assert.equal(SecUtil.intToHex(new BN(0)), '0x0')
  })
  it('should convert a int to hex', () => {
    const i = 6003400
    const hex = SecUtil.intToHex(i)
    assert.equal(hex, '0x5b9ac8')
  })
})

describe('intToBuffer', () => {
  it('should convert a int to a buffer', () => {
    const i = 6003400
    const buf = SecUtil.intToBuffer(i)
    assert.equal(buf.toString('hex'), '5b9ac8')
  })

  it('should convert a int to a buffer for odd length hex values', () => {
    const i = 1
    const buf = SecUtil.intToBuffer(i)
    assert.equal(buf.toString('hex'), '01')
  })
})

describe('entropyToMnemonic', () => {
  it('should tranlate 12 - 24 random english word', () => {
    const string64 = '4400f53d8349b80fdae44082d7f9541e1dba2b003bcfec9d0d53781ca676651f'
    assert.equal(SecUtil.entropyToMnemonic(string64), 'dune amateur exhaust alley oppose among high marine lizard save fence destroy sweet better abstract ketchup uncle trick feel usual skill depth nerve wine')
  })
})

describe('mnemonicToEntropy', () => {
  it('should tranlate 64 strings', () => {
    const englishWord = 'dune amateur exhaust alley oppose among high marine lizard save fence destroy sweet better abstract ketchup uncle trick feel usual skill depth nerve wine'
    assert.equal(SecUtil.mnemonicToEntropy(englishWord), '4400f53d8349b80fdae44082d7f9541e1dba2b003bcfec9d0d53781ca676651f')
  })
})
