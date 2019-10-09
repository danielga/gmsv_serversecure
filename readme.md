# gmsv_serversecure

[![Build Status](https://travis-ci.org/danielga/gmsv_serversecure.svg?branch=master)](https://travis-ci.org/danielga/gmsv_serversecure)  
[![Build status](https://ci.appveyor.com/api/projects/status/pasfddwn1oboem7m?svg=true)](https://ci.appveyor.com/project/danielga/gmsv-serversecure)  
A module for Garry's Mod that mitigates exploits on the Source engine.  
Based on these plugins from AzuiSleet:  
[serverplugin_serversecure][1]  
[serverplugin_serversecure2][2]  
[serversecure3][3]  

## Compiling

The only supported compilation platform for this project on Windows is **Visual Studio 2017** on **release** mode.  
On Linux, everything should work fine as is, on **release** mode.  
For Mac OSX, any **Xcode (using the GCC compiler)** version *MIGHT* work as long as the **Mac OSX 10.5 SDK** is used, on **release** mode.  
These restrictions are not random; they exist because of ABI compatibility reasons.  
If stuff starts erroring or fails to work, be sure to check the correct line endings (\n and such) are present in the files for each OS.  

## Requirements

This project requires [garrysmod_common][4], a framework to facilitate the creation of compilations files (Visual Studio, make, XCode, etc). Simply set the environment variable '**GARRYSMOD\_COMMON**' or the premake option '**gmcommon**' to the path of your local copy of [garrysmod_common][4].  
We also use [SourceSDK2013][5], so set the environment variable '**SOURCE\_SDK**' or the premake option '**sourcesdk**' to the path of your local copy of [SourceSDK2013][5]. The previous links to [SourceSDK2013][5] point to my own fork of VALVe's repo and for good reason: Garry's Mod has lots of backwards incompatible changes to interfaces and it's much smaller, being perfect for automated build systems like Travis-CI (which is used for this project).  

  [1]: http://gmodmodules.googlecode.com/svn/trunk/serverplugin_serversecure
  [2]: http://gmodmodules.googlecode.com/svn/trunk/serverplugin_serversecure2
  [3]: http://gmodmodules.googlecode.com/svn/trunk/serversecure3
  [4]: https://github.com/danielga/garrysmod_common
  [5]: https://github.com/danielga/sourcesdk-minimal
