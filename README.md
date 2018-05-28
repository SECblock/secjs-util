<a name="SecUtils"></a>
* * *
## SecUtils
[![JavaScript Style Guide](https://cdn.rawgit.com/standard/standard/master/badge.svg)](https://github.com/standard/standard) 
![Travis](https://img.shields.io/travis/USER/REPO.svg)

**Definition**: A collection of utility functions for secblock. It can be used in node.js or can be in the browser with browserify. -->
**Install**
```sh
npm install SecUtils --save (t.b.d)
```
**Usage**
```sh
class SecUtils {
    ...
    func1()
    ...
}

const Utils = new SecUtils() // define a smiple constant
SecUtils.func1()            // callback
```
* * *
### UnixTime()
A utility function of getting a Unix timestamp from using for the UnixTime(), which is integrated of an error-showing process.
### DateTime()
A utility function of getting a standard GMT time from using for the DateTime(), which is integrated of an error-showing process.
### 

### LICENSE
MPL-2.0


* * *
# SEC工具库-中文简介

Utils英语Utility（意思为功能，工具）的复数Utilities的简写；是区块链开发的工具库，内部由封装了多个功能函数（例如获取时间戳函数UnixTime等）的库组成；其作用是为进一步开发提供可直接调用的函数，使整个系统轻量、高效。
----
主要的函数及其用途：
1.  定义UnixTime()和DateTime()函数, 分别代表Unix时间戳和GMT（格林尼治）标准时间；可在下一步SEC区块数据结构和交易流程的开发中直接调用。
2.  定义
3.  定义