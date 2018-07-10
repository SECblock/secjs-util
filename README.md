<a name="SecUtils"></a>

* * *
## SecUtils
[![JavaScript Style Guide](https://cdn.rawgit.com/standard/standard/master/badge.svg)](https://github.com/standard/standard) 

**Definition**: 
A collection of utility functions for secblock. It can be used in node.js or can be in the browser with browserify. -->

**Kind**: global class
* [SecUtils](#SecUtils)
    * [.currentUnixTimeInMillisecond()](#currentUnixTimeInMillisecond)
    * [.currentUnixTimeSecond()](#currentUnixTimeSecond)
    * [.getDatetime()](#getDatetime) 
    * [.getUnixtime()](#getUnixtime)
    * [.asyncGetUTCTimeFromServer()](#asyncGetUTCTimeFromServer) 
    * [.refreshTimeDifference(callback)](#refreshTimeDifference)
    * [.hasha256(data)](#secUtil+hasha256)
    * [.generatePrivateKey()](#secUtil+generatePrivateKey)
    * [.generatePublicKey(key, addrVer)](#secUtil+generatePublicKey)
    * [.generateAddress(publicKey, addrVer)](#secUtil+generateAddress)
    * [.getPrivateKey()](#secUtil+getPrivateKey)
    * [.generateContractAddress(from, nonce)](#generateContractAddress)
    * [.defineProperties(self, fields, data)](#defineProperties)
    * [.padToEven(value)](#padToEven)    
    * [.toBuffer(v)](#toBuffer)
    * [.baToJSON(ba)](#baToJSON)
    * [.stripZeros(a)](#stripZeros)    
    * [.unpad(a)](#unpad)
    * [.isHexString(value, length)](#isHexString)
    * [.intToBuffer(i)](#intToBuffer)    
    * [.intToHex(i)](#intToHex)
    * [.rlphash(a)](#rlphash)
    * [.keccak(a, bits)](#keccak)    
    * [.zeros(bytes)](#zeros)
    * [.getBinarySize(str)](#getBinarySize)    
    * [.arrayContainsArray(superset, subset, some)](#arrayContainsArray)
    * [.toUtf8(hex)](#toUtf8)
    * [.toAscii(hex)](#toAscii)    
    * [.fromUtf8(stringValue)](#fromUtf8)
    * [.fromAscii(stringValue)](#fromAscii)
    * [.getKeys(params, key, allowEmpty)](#getKeys)    
    * [.bufferToHex(buf)](#bufferToHex)
    * [.zeroAddress()](#zeroAddress)
    * [.setLengthLeft(msg, length, right)](#setLengthLeft)    
    * [.setLength(msg, length, right)](#setLength)
    * [.setLengthRight(msg, length)](#setLengthRight)
    * [.bufferToInt(buf)](#bufferToInt)    
    * [.fromSigned(num)](#fromSigned)
    * [.toUnsigned(num)](#toUnsigned)
    * [.keccak256(a)](#keccak256)    
    * [.sha3()](#sha3)
    * [.sha256()](#sha256)
    * [.ripemd160(a, padded)](#ripemd160)    
    * [.isValidPrivate(privateKey)](#isValidPrivate)
    * [.isValidPublic(publicKey, sanitize)](#isValidPublic)
    * [.publicToAddress(pubKey, sanitize)](#publicToAddress)    
    * [.privateToPublic(privateKey)](#privateToPublic)
    * [.importPublic(publicKey)](#importPublic)
    * [.ecsign(msgHash,privatekey)](#ecsign)    
    * [.hashPersonalMessage(message)](#hashPersonalMessage)
    * [.ecrecover(msghash,v,r,s)](#ecrecover)
    * [.toRpcSig(v,r,s)](#toRpcSig)    
    * [.fromRpcSig(sig)](#fromRpcSig)
    * [.privateToAddress(privateKey)](#privateToAddress)
    * [.isValidAddress(address)](#isValidAddress)
    * [.isZeroAddress(address)](#isZeroAddress)
    * [.toChecksumAddress(address)](#toChecksumAddress)
    * [.isValidChecksumAddress(address)](#isValidChecksumAddress)
    * [.isPrecompiled(address)](#isPrecompiled)
    * [.addHexPrefix(str)](#addHexPrefix)
    * [.isValidSignature(v, r, s, homestead)](#isValidSignature)
    * [.stripHexPrefix(str)](#stripHexPrefix)

* * *
**Install**
```js
npm install @sec-block/secjs-util --save 
```

**Usage**
```js
class SecUtils {
    ...
    func1()
    func2()
    ...
}
const util = new SecUtils() 
util.func1()           
```

* * *
<a name="UnixTime"></a>

### UnixTime
A utility function of getting a Unix timestamp from using for the UnixTime(), which is integrated with an error handling process.

**Example**
```js
const SecUtils = require('../src/index')
const util = new SecUtils()
util.UnixTime()
```

* * *
<a name="getDatetime"></a>

### getDatetime
A utility function of converting a standard GMT time to a Unix timestamp.

**Example**
```js
const SecUtils = require('../src/index')
const util = new SecUtils({
    timeServer: 'DE'
})
util.getDatetime()
```
* * *
<a name="getUnixtime"></a>

### getUnixtime
A utility function of converting a Unix timestamp to a standard GMT time.

**Example**
```js
const SecUtils = require('../src/index')
const util = new SecUtils({
    timeServer: 'DE'
})
util.getUnixtime()
```

* * *
<a name="asyncGetUTCTimeFromServer"></a>

### asyncGetUTCTimeFromServer
A utility function of get utc time from ntp server.

**Example**
```js
const SecUtils = require('../src/index')
const util = new SecUtils({
    timeServer: 'DE'
})
util.asyncGetUTCTimeFromeServer().then(callback).catch(err)
```

* * *
<a name="refreshTimeDifference"></a>

### refreshTimeDifference
A utility function to refresh the time difference between local host and ntp server.

**Example**
```js
const SecUtils = require('../src/index')
const util = new SecUtils({
    timeServer: 'DE'
})
util.refreshTimeDifference( (err, timeDiff) => {
    if (err) {
        console.log(err)
    }
    console.log(timeDiff)
})
```


<a name="secUtil+hasha256"></a>

### hasha256(data)
A small function created as there is a lot of sha256 hashing.

**Kind**: instance method of [<code>secUtil</code>](#secUtil)  

| Param | Type | Description |
| --- | --- | --- |
| data | <code>Buffer</code> | creat sha256 hash buffer |

<a name="secUtil+generatePrivateKey"></a>

### generatePrivateKey()
0x00 P2PKH Mainnet, 0x6f P2PKH Testnet
0x80 Mainnet, 0xEF Testnet （or Test Network: 0x6f and Namecoin Net:0x34）
generate private key through sha256 random values. and translate to hex
get usedful private key. It will be used for secp256k1
generate check code. two times SHA256 at privatKey.
base58(privat key + the version number + check code).
it is used as WIF(Wallet import Format) privatKey

**Kind**: instance method of [<code>secUtil</code>](#secUtil)  
<a name="secUtil+generatePublicKey"></a>

### generatePublicKey(key, addrVer)
generate public key

**Kind**: instance method of [<code>secUtil</code>](#secUtil)  

| Param | Type | Description |
| --- | --- | --- |
| key | <code>Buffer</code> |  |
| addrVer | <code>Buffer</code> | input addVer from generatePrivateKey() set elliptic point and x,y axis not sure whether useful let x = pubPoint.getX() let y = pubPoint.getY() use secp256k1. generate public key structe public key: 1(network ID) + 32bytes(from x axis) + 32bytes(from y axis) ripemd160(sha256(public key)) |

<a name="secUtil+generateAddress"></a>

### generateAddress(publicKey, addrVer)
double sha256 generate hashExtRipe2. sha256(sha256(version number + hashBuffer)).
the first 4 bytes of hashExtRipe2 are used as a checksum and placed at the end of
the 21 byte array. structe secBinary: 1(network ID) + concatHash + 4 byte(checksum)

**Kind**: instance method of [<code>secUtil</code>](#secUtil)  

| Param | Type | Description |
| --- | --- | --- |
| publicKey | <code>Buffer</code> | input public key from generatePublicKey() |
| addrVer | <code>Buffer</code> | input addVer from generatePrivateKey() generate WIF private key and translate to hex generate SEC Address and translate to hex |

<a name="secUtil+getPrivateKey"></a>

### getPrivateKey()
return four private key, wif private key, public key
and sec address

**Kind**: instance method of [<code>secUtil</code>](#secUtil)  
### LICENSE
MPL-2.0

* * *
### generateContractAddress
A utility function of generating an address of a newly created contract

**Example**
```js
const SecUtils = require('../src/index')
const util = new SecUtils({
    timeServer: 'DE'
})
util.generateContractAddress(from, nonce)
```

<a name="defineProperties"></a>
* * *
### defineProperties
A utility function of generating an address of a newly created contract

**Example**
```js
const SecUtils = require('../src/index')
const util = new SecUtils({
    timeServer: 'DE'
})
util.defineProperties(from, nonce)
```
* * *

    * [.getUnixtime()](#getUnixtime) 
<a name="getUnixtime"></a>

### getUnixtime
A utility function of converting a Unix timestamp to a standard GMT time.

**Example**
```js
const SecUtils = require('../src/index')
const util = new SecUtils({
    timeServer: 'DE'
})
util.getUnixtime()
```
* * *
<a name="generateContractAddress"></a>

### generateContractAddress
A utility function of generating an address of a newly created contract

**Example**
```js
const SecUtils = require('../src/index')
const util = new SecUtils({
    timeServer: 'DE'
})
util.generateContractAddress(from, nonce)
```

* * *
<a name="defineProperties"></a>

### defineProperties
Defines properties on a Object. It make the assumption that underlying data is binary.

**Example**
```js
const SecUtils = require('../src/index')
const util = new SecUtils({
    timeServer: 'DE'
})
util.defineProperties()
```
* * *
<a name="padToEven"></a>

### padToEven
A utility function of adding a value in type of string. 

**Example**
```js
const SecUtils = require('../src/index')
const util = new SecUtils({
    timeServer: 'DE'
})
util.padToEven(value)
```
* * *
<a name="toBuffer"></a>

### toBuffer
A utility function of adding a value to buffer.

**Example**
```js
const SecUtils = require('../src/index')
const util = new SecUtils({
    timeServer: 'DE'
})
util.toBuffer(v)
```
* * *
<a name="baToJSON"></a>

### baToJSON
A utility function of converting buffer value to JSON format.

**Example**
```js
const SecUtils = require('../src/index')
const util = new SecUtils({
    timeServer: 'DE'
})
util.baToJSON(from, nonce)
```
* * *
<a name="stripZeros"></a>

### stripZeros
A utility function of stripping zeros.

**Example**
```js
const SecUtils = require('../src/index')
const util = new SecUtils({
    timeServer: 'DE'
})
util.stripZeros(a)
```
* * *
<a name="unpad"></a>

### unpad
A utility function of leading zeros from a `Buffer` or an `Array`.

**Example**
```js
const SecUtils = require('../src/index')
const util = new SecUtils({
    timeServer: 'DE'
})
util.unpad(a)
```
* * *
<a name="isHexString"></a>

### isHexString
A utility function of confirming a hex string.

**Example**
```js
const SecUtils = require('../src/index')
const util = new SecUtils({
    timeServer: 'DE'
})
util.isHexString(value, length)
```
* * *
<a name="intToBuffer"></a>

### intToBuffer
A utility function of converting a `Number` to a `Buffer`.

**Example**
```js
const SecUtils = require('../src/index')
const util = new SecUtils({
    timeServer: 'DE'
})
util.intToBuffer(i)
```
* * *
<a name="intToHex"></a>

### intToHex
A utility function of converting `Number` into a hex `String`.

**Example**
```js
const SecUtils = require('../src/index')
const util = new SecUtils({
    timeServer: 'DE'
})
util.intToHex(i)
```
* * *
<a name="rlphash"></a>

### rlphash
A utility function of creating SHA-3 hash of the RLP encoded version of the input.

**Example**
```js
const SecUtils = require('../src/index')
const util = new SecUtils({
    timeServer: 'DE'
})
util.rlphash(a)
```
* * *
<a name="keccak"></a>

### keccak
A utility function of creating Keccak hash of the input.

**Example**
```js
const SecUtils = require('../src/index')
const util = new SecUtils({
    timeServer: 'DE'
})
util.keccak(a, bits)
```
* * *
<a name="zeros"></a>

### zeros
A utility function of returning a buffer filled with 0s.

**Example**
```js
const SecUtils = require('../src/index')
const util = new SecUtils({
    timeServer: 'DE'
})
util.zeros(bytes)
```
* * *
<a name="getBinarySize"></a>

### getBinarySize
A utility function of getting the binary size of a string.

**Example**
```js
const SecUtils = require('../src/index')
const util = new SecUtils({
    timeServer: 'DE'
})
util.getBinarySize(str)
```
* * *
<a name="arrayContainsArray"></a>

### arrayContainsArray
A utility function of returning 'TRUE' if the first specified array contains all elements from the second one and returning 'FALSE' otherwise.

**Example**
```js
const SecUtils = require('../src/index')
const util = new SecUtils({
    timeServer: 'DE'
})
util.arrayContainsArray(superset, subset, some)
```
* * *
<a name="toUtf8"></a>

### toUtf8
A utility function of getting utf8 from its hex representation.

**Example**
```js
const SecUtils = require('../src/index')
const util = new SecUtils({
    timeServer: 'DE'
})
util.toUtf8(hex)
```
* * *
<a name="toAscii"></a>

### toAscii
A utility function of getting ascii from its hex representation.

**Example**
```js
const SecUtils = require('../src/index')
const util = new SecUtils({
    timeServer: 'DE'
})
util.toAscii(hex)
```
* * *
<a name="fromUtf8"></a>

### fromUtf8
A utility function of getting hex representation (prefixed by 0x) of utf8 string.

**Example**
```js
const SecUtils = require('../src/index')
const util = new SecUtils({
    timeServer: 'DE'
})
util.fromUtf8(stringValue)
```
* * *
<a name="fromAscii"></a>

### fromAscii
A utility function of getting hex representation (prefixed by 0x) of ascii string.

**Example**
```js
const SecUtils = require('../src/index')
const util = new SecUtils({
    timeServer: 'DE'
})
util.fromAscii(stringValue)
```
* * *
<a name="getKeys"></a>

### getKeys
A utility function of getting specific key from inner object array of objects.

**Example**
```js
const SecUtils = require('../src/index')
const util = new SecUtils({
    timeServer: 'DE'
})
util.getKeys(params, key, allowEmptyfrom)
```
* * *
<a name="bufferToHex"></a>

### bufferToHex
A utility function of converting a `Buffer` into a hex `String`.

**Example**
```js
const SecUtils = require('../src/index')
const util = new SecUtils({
    timeServer: 'DE'
})
util.bufferToHex(buff)
```
* * *
<a name="zeroAddress"></a>

### zeroAddress
A utility function of returning a zero address.

**Example**
```js
const SecUtils = require('../src/index')
const util = new SecUtils({
    timeServer: 'DE'
})
util.zeroAddress()
```
* * *
<a name="setLengthLeft"></a>

### setLengthLeft
A utility function of left padding an `Array` or `Buffer` with leading zeros till it has `length` bytes.

**Example**
```js
const SecUtils = require('../src/index')
const util = new SecUtils({
    timeServer: 'DE'
})
util.setLengthLeft(msg, length, right)
```
* * *
<a name="setLength"></a>

### setLength
A utility function of padding an `Array` or `Buffer` with leading zeros till it has `length` bytes.

**Example**
```js
const SecUtils = require('../src/index')
const util = new SecUtils({
    timeServer: 'DE'
})
util.setLength(msg, length, right)
```
* * *
<a name="setLengthRight"></a>

### setLengthRight
A utility function of right padding an `Array` or `Buffer` with leading zeros till it has `length` bytes. Or it truncates the beginning if it exceeds.

**Example**
```js
const SecUtils = require('../src/index')
const util = new SecUtils({
    timeServer: 'DE'
})
util.setLengthRight(msg, length)
```
* * *
<a name="bufferToInt"></a>

### bufferToInt
A utility function of Converting a `Buffer` to a `Number`.

**Example**
```js
const SecUtils = require('../src/index')
const util = new SecUtils({
    timeServer: 'DE'
})
util.bufferToInt(buf)
```
* * *
<a name="fromSigned"></a>

### fromSigned
A utility function of interpreting a `Buffer` as a signed integer and returns a `BN`. Assumes 256-bit numbers.

**Example**
```js
const SecUtils = require('../src/index')
const util = new SecUtils({
    timeServer: 'DE'
})
util.fromSigned(num)
```
* * *
<a name="toUnsigned"></a>

### toUnsigned
A utility function of converting a `BN` to an unsigned integer and returns it as a `Buffer`. Assumes 256-bit numbers.

**Example**
```js
const SecUtils = require('../src/index')
const util = new SecUtils({
    timeServer: 'DE'
})
util.toUnsigned(num)
```
* * *
<a name="keccak256"></a>

### keccak256
A utility function of creating Keccak-256 hash of the input, alias for keccak(a, 256).

**Example**
```js
const SecUtils = require('../src/index')
const util = new SecUtils({
    timeServer: 'DE'
})
util.keccak256(a)
```
* * *
<a name="sha3"></a>

### sha3
A utility function of creating a keccak hash of input.

**Example**
```js
const SecUtils = require('../src/index')
const util = new SecUtils({
    timeServer: 'DE'
})
util.sha3()
```
* * *
<a name="sha256"></a>

### sha256
A utility function of creating SHA256 hash of the input.

**Example**
```js
const SecUtils = require('../src/index')
const util = new SecUtils({
    timeServer: 'DE'
})
util.sha256(a)
```
* * *
<a name="ripemd160"></a>

### ripemd160
A utility function of creating RIPEMD160 hash of the input.

**Example**
```js
const SecUtils = require('../src/index')
const util = new SecUtils({
    timeServer: 'DE'
})
util.ripemd160(a,padded)
```
* * *
<a name="isValidPrivate"></a>

### isValidPrivate
A utility function of checking if the private key satisfies the rules of the curve secp256k1.

**Example**
```js
const SecUtils = require('../src/index')
const util = new SecUtils({
    timeServer: 'DE'
})
util.isValidPrivate(privateKey)
```
* * *
<a name="isValidPublic"></a>

### isValidPublic
A utility function of checking if the public key satisfies the rules of the curve secp256k1 and the requirements of SEC.

**Example**
```js
const SecUtils = require('../src/index')
const util = new SecUtils({
    timeServer: 'DE'
})
util.isValidPublic(publicKey, sanitize)
```
* * *
<a name="publicToAddress"></a>

### publicToAddress
A utility function of returning the SEC address of a given public key accepting "SEC public keys" and SEC1 encoded keys.

**Example**
```js
const SecUtils = require('../src/index')
const util = new SecUtils({
    timeServer: 'DE'
})
util.publicToAddress(pubKey, sanitize)
```
* * *
<a name="privateToPublic"></a>

### privateToPublic
A utility function of returning the SEC public key of a given private key.

**Example**
```js
const SecUtils = require('../src/index')
const util = new SecUtils({
    timeServer: 'DE'
})
util.privateToPublic(privateKey)
```
* * *
<a name="importPublic"></a>

### importPublic
A utility function of converting a public key to the SEC format.

**Example**
```js
const SecUtils = require('../src/index')
const util = new SecUtils({
    timeServer: 'DE'
})
util.importPublic(publicKey)
```
* * *
<a name="ecsign"></a>

### ecsign
A utility function of ECDSA sign.

**Example**
```js
const SecUtils = require('../src/index')
const util = new SecUtils({
    timeServer: 'DE'
})
util.ecsign(msgHash, privateKey)
```
* * *
<a name="hashPersonalMessage"></a>

### hashPersonalMessage
A utility function of Returns the keccak-256 hash of `message`, prefixed with the header used by the `SEC_sign` RPC call. The output of this function can be fed into `ecsign` to produce the same signature as the `SEC_sign` call for a given `message`, or fed to `ecrecover` along with a signature to recover the public key used to produce the signature.

**Example**
```js
const SecUtils = require('../src/index')
const util = new SecUtils({
    timeServer: 'DE'
})
util.hashPersonalMessage(message)
```
* * *
<a name="ecrecover"></a>

### ecrecover
A utility function of ECDSA public key recovery from signature.

**Example**
```js
const SecUtils = require('../src/index')
const util = new SecUtils({
    timeServer: 'DE'
})
util.ecrecover(msgHash, v, r, s)
```
* * *
<a name="toRpcSig"></a>

### toRpcSig
A utility function of converting signature parameters into the format of `SEC_sign` RPC method.

**Example**
```js
const SecUtils = require('../src/index')
const util = new SecUtils({
    timeServer: 'DE'
})
util.toRpcSig(v, r, s)
```
* * *
<a name="fromRpcSig"></a>

### fromRpcSig
A utility function of converting signature format of the `SEC_sign` RPC method to signature parameters.

**Example**
```js
const SecUtils = require('../src/index')
const util = new SecUtils({
    timeServer: 'DE'
})
util.fromRpcSig(sig)
```
* * *
<a name="privateToAddress"></a>

### privateToAddress
A utility function of returning the SEC address of a given private key.

**Example**
```js
const SecUtils = require('../src/index')
const util = new SecUtils({
    timeServer: 'DE'
})
util.privateToAddress(privateKey)
```
* * *
<a name="isValidAddress"></a>

### isValidAddress
A utility function of checking if the address is a valid. Accepts checksummed addresses too.

**Example**
```js
const SecUtils = require('../src/index')
const util = new SecUtils({
    timeServer: 'DE'
})
util.isValidAddress(address)
```
* * *
<a name="isZeroAddress"></a>

### isZeroAddress
A ultiity function of checking if a given address is a zero address.

**Example**
```js
const SecUtils = require('../src/index')
const util = new SecUtils({
    timeServer: 'DE'
})
util.isZeroAddress(address)
```
* * *
<a name="toChecksumAddress"></a>

### toChecksumAddress
A utility function of returning a checksummed address.

**Example**
```js
const SecUtils = require('../src/index')
const util = new SecUtils({
    timeServer: 'DE'
})
util.toChecksumAddress(address)
```
* * *
<a name="isValidChecksumAddress"></a>

### isValidChecksumAddress
A utility function of checking if the address is a valid checksummed address.

**Example**
```js
const SecUtils = require('../src/index')
const util = new SecUtils({
    timeServer: 'DE'
})
util.isValidChecksumAddress(address)
```
* * *
<a name="isPrecompiled"></a>

### isPrecompiled
A utility function of returning true if the supplied address belongs to a precompiled account (Byzantium).

**Example**
```js
const SecUtils = require('../src/index')
const util = new SecUtils({
    timeServer: 'DE'
})
util.isPrecompiled(address)
```
* * *
<a name="addHexPrefix"></a>

### addHexPrefix
A utility function of adding "0x" to a given `String` if it does not already start with "0x".

**Example**
```js
const SecUtils = require('../src/index')
const util = new SecUtils({
    timeServer: 'DE'
})
util.addHexPrefix(str)
```
* * *
<a name="isValidSignature"></a>

### isValidSignature
A utility function of validating ECDSA signature.

**Example**
```js
const SecUtils = require('../src/index')
const util = new SecUtils({
    timeServer: 'DE'
})
util.isValidSignature(v, r, s, homestead)
```
* * *
<a name="stripHexPrefix"></a>

### stripHexPrefix
A utility function of stripping hex sting.

**Example**
```js
const SecUtils = require('../src/index')
const util = new SecUtils({
    timeServer: 'DE'
})
util.stripHexPrefix()
```

* * *
# SEC工具库-中文简介

Utils，是英语Utility（意思是功能，工具）的复数，Utilities的简写；是区块链开发的工具库；是内部由封装了多个功能函数（例如获取时间戳函数UnixTime等）的库组成。其作用是为进一步开发提供可直接调用的函数，使整个SEC区块链系统轻量、高效。
主要的函数及其用途：

1.  定义方法UnixTime()
	代表Unix时间戳；可在下一步SEC区块数据结构和交易流程的开发中直接调用。

2.  定义方法getDatetime()
	将任意一个Unix时间戳转换为标准时间
	
3.  定义方法getUnixtime()
	将任意一个标准时间转化为Unix时间



SEC地址是为了减少接收方所需标识的字节数。SEC地址（secAddress）的生成步骤如下：

1. 将公钥通过SHA256哈希算法处理得到32字节的哈希值，
2. 后对得到的哈希值通过RIPEMD-160算法来得到20字节的哈希值 —— Hash160  即ripemd160（sha256（publicKey））
3. 把版本号[2]+Hash160组成的21字节数组进行双次SHA256哈希运算，得到的哈希值的头4个字节作为校验和，放置21字节数组的末尾。
4. 对组成25位数组进行Base58编码，就得到地址。