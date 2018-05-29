<a name="SecUtils"></a>

* * *
## SecUtils
[![JavaScript Style Guide](https://cdn.rawgit.com/standard/standard/master/badge.svg)](https://github.com/standard/standard) 

**Definition**: 
A collection of utility functions for secblock. It can be used in node.js or can be in the browser with browserify. -->

**Kind**: global class
* [SecUtils](#SecUtils)
    * [.UnixTime()](#UnixTime) ⇒ <code>Array.&lt;Buffer&gt;</code>
    * [.DateTime()](#DateTime) ⇒ <code>Array.&lt;Buffer&gt;</code>
    * 
    * 
    * 

**Install**
```js
npm install SecUtils --save (t.b.d)
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
const MerkleTree = require('../src/index')
const util = new SecUtils()
util.UnixTime()
```

* * *
<a name="DateTime"></a>

### DateTime
A utility function of getting a standard GMT time from using for the DateTime(), which is integrated with an error handling process.

**Example**
```js
const MerkleTree = require('../src/index')
const util = new SecUtils()
util.DateTime()
```

### LICENSE
MPL-2.0

* * *
# SEC工具库-中文简介

Utils，是英语Utility（意思是功能，工具）的复数，Utilities的简写；是区块链开发的工具库；是内部由封装了多个功能函数（例如获取时间戳函数UnixTime等）的库组成。其作用是为进一步开发提供可直接调用的函数，使整个SEC区块链系统轻量、高效。
主要的函数及其用途：

1.  定义方法UnixTime()和DateTime()
	分别代表Unix时间戳和GMT（格林尼治）标准时间；可在下一步SEC区块数据结构和交易流程的开发中直接调用。

2.  定义方法
	
	
3.  定义方法
	