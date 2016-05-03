if os.is("windows") and _ACTION ~= "vs2010" then
	error("The only supported compilation platform for this project on Windows is Visual Studio 2010.")
elseif os.is("linux") then
	print("WARNING: The only supported compilation platforms (tested) for this project on Linux are GCC/G++ 4.8 or 4.9. However, any version between 4.4 and 4.9 *MIGHT* work.")
elseif os.is("macosx") then
	print("WARNING: The only supported compilation platform (tested) for this project on Mac OSX is Xcode 4.1. However, any Xcode version *MIGHT* work as long as the Mac OSX 10.6 SDK is used (https://github.com/phracker/MacOSX-SDKs/releases/download/MacOSX10.11.sdk/MacOSX10.6.sdk.tar.xz).")

	newoption({
		trigger = "macosxsdk",
		description = "Sets the path to the Mac OSX 10.6 SDK (https://github.com/phracker/MacOSX-SDKs) directory",
		value = "path to Mac OSX 10.6 SDK directory"
	})
end

newoption({
	trigger = "gmcommon",
	description = "Sets the path to the garrysmod_common (https://github.com/danielga/garrysmod_common) directory",
	value = "path to garrysmod_common directory"
})

local gmcommon = _OPTIONS.gmcommon or os.getenv("GARRYSMOD_COMMON")
if gmcommon == nil then
	error("you didn't provide a path to your garrysmod_common (https://github.com/danielga/garrysmod_common) directory")
end

include(gmcommon)

CreateSolution({name = "serversecure", allow_debug = false})
	CreateProject({serverside = true})
		warnings("Default")
		IncludeSDKCommon()
		IncludeSDKTier0()
		IncludeSDKTier1()
		IncludeSteamAPI()
		IncludeDetouring()
		IncludeScanning()

		filter("system:macosx")
			buildoptions({
				"-mmacosx-version-min=10.5",
				"--sysroot=" .. (_OPTIONS.macosxsdk or os.getenv("MACOSX_SDK") or path.getabsolute("macosx/MacOSX10.6.sdk"))
			})
