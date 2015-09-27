newoption({
	trigger = "gmcommon",
	description = "Sets the path to the garrysmod_common (https://bitbucket.org/danielga/garrysmod_common) directory",
	value = "path to garrysmod_common dir"
})

local gmcommon = _OPTIONS.gmcommon or os.getenv("GARRYSMOD_COMMON")
if gmcommon == nil then
	error("you didn't provide a path to your garrysmod_common (https://bitbucket.org/danielga/garrysmod_common) directory")
end

include(gmcommon)

CreateSolution("serversecure")
	CreateProject(SERVERSIDE)
		warnings("Default")
		IncludeSourceSDK()
		IncludeSteamAPI()
		IncludeDetouring()
		IncludeScanning()
