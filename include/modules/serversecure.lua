require("serversecure.core")

local format, match, band, rshift = string.format, string.match, bit.band, bit.rshift

serversecure.Version = "serversecure 1.5.20"
serversecure.VersionNum = 10520

function serversecure.IPToString(uint)
	if not uint then
		return
	end

	local a, b, c, d =
		band(rshift(uint, 24), 0xFF),
		band(rshift(uint, 16), 0xFF),
		band(rshift(uint, 8), 0xFF),
		band(uint, 0xFF)
	return format("%d.%d.%d.%d", d, c, b, a)
end

function serversecure.StringToIP(str)
	if not str then
		return
	end

	local a, b, c, d = match(str, "^(%d+)%.(%d+)%.(%d+)%.(%d+)")
	if not d then
		return
	end

	return ((d * 256 + c) * 256 + b) * 256 + a
end

function serversecure.PostInitialize()
	print("[ServerSecure] serversecure.PostInitialize is deprecated since it's not needed anymore!")
	return true
end

hook.Add("Initialize", "serversecure.FixGameDescription", function()
	serversecure.RefreshInfoCache()
end)
