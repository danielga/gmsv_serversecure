# gmsv_serversecure

A module for Garry's Mod that mitigates exploits on the Source engine.
Based on these plugins from AzuiSleet:
[serverplugin_serversecure][1]
[serverplugin_serversecure2][2]
[serversecure3][3]

## Info

Mac was not tested at all (sorry but I'm poor).

If stuff starts erroring or fails to work, be sure to check the correct line endings (\n and such) are present in the files for each OS.

This project requires [garrysmod_common][4], a framework to facilitate the creation of compilations files (Visual Studio, make, XCode, etc). Simply set the environment variable 'GARRYSMOD_COMMON' or the premake option 'gmcommon' to the path of your local copy of [garrysmod_common][4]. We also use [SourceSDK2013][5], so set the environment variable 'SOURCE_SDK' or the premake option 'sourcesdk' to the path of your local copy of [SourceSDK2013][5].


  [1]: http://gmodmodules.googlecode.com/svn/trunk/serverplugin_serversecure
  [2]: http://gmodmodules.googlecode.com/svn/trunk/serverplugin_serversecure2
  [3]: http://gmodmodules.googlecode.com/svn/trunk/serversecure3
  [4]: https://bitbucket.org/danielga/garrysmod_common
  [5]: https://github.com/ValveSoftware/source-sdk-2013
