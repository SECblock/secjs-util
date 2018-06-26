<a name="SecUtils"></a>

* * *
## SecUtils
[![JavaScript Style Guide](https://cdn.rawgit.com/standard/standard/master/badge.svg)](https://github.com/standard/standard) 

**Definition**: 
A collection of utility functions for secblock. It can be used in node.js or can be in the browser with browserify. -->

**Kind**: global class
* [SecUtils](#SecUtils)
    * [.UnixTime()](#UnixTime) ⇒ <code>Array.&lt;Buffer&gt;</code>
    * [.getDatetime()](#getDatetime) ⇒ <code>Array.&lt;Buffer&gt;</code>
    * [.getUnixtime()](#getUnixtime) ⇒ <code>Array.&lt;Buffer&gt;</code>
    * [.hasha256(data)](#secUtil+hasha256)
    * [.generatePrivateKey()](#secUtil+generatePrivateKey)
    * [.generatePublicKey(key, addrVer)](#secUtil+generatePublicKey)
    * [.generateAddress(publicKey, addrVer)](#secUtil+generateAddress)
    * [.getPrivateKey()](#secUtil+getPrivateKey)

**Install**
```js
npm install @sec-block/secjs-util --save (t.b.d)
```

**Usage**
```js
class SecUtils {
    ...
    func1()
    func2()
    ...
}
const util = new SecUtils() // define a smiple constant
util.func1()            // call the function
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