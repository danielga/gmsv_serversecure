PROJECT_GENERATOR_VERSION = 2

newoption({
	trigger = "gmcommon",
	description = "Sets the path to the garrysmod_common (https://github.com/danielga/garrysmod_common) directory",
	value = "../garrysmod_common"
})

local gmcommon = assert(_OPTIONS.gmcommon or os.getenv("GARRYSMOD_COMMON"),
	"you didn't provide a path to your garrysmod_common (https://github.com/danielga/garrysmod_common) directory")
include(gmcommon)

CreateWorkspace({name = "serversecure.core", abi_compatible = true})
	CreateProject({serverside = true})
		IncludeLuaShared()
		IncludeHelpersExtended()
		IncludeSDKCommon()
		IncludeSDKTier0()
		IncludeSDKTier1()
		IncludeSteamAPI()
		IncludeDetouring()
		IncludeScanning()
		files({
			"source/netfilter/*.cpp",
			"source/netfilter/*.hpp"
		})

	group("")
		project("testing")
			kind("ConsoleApp")
			includedirs({"source", "source/testing"})
			files({
				"source/netfilter/client.cpp",
				"source/netfilter/client.hpp",
				"source/netfilter/clientmanager.cpp",
				"source/netfilter/clientmanager.hpp",
				"source/netfilter/objectpool.hpp",
				"source/testing/*.cpp",
				"source/testing/*.hpp"
			})
