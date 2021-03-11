require("serversecure.core")

--serversecure.EnableFirewallWhitelist(boolean) -- enable "firewall" whitelist, any client not in the whitelist doesn't see the server
--serversecure.AddWhitelistIP(ip_in_integer_format) -- add an IP to the whitelist
--serversecure.RemoveWhitelistIP(ip_in_integer_format) -- remove an IP from the whitelist
--serversecure.ResetWhitelist() -- reset the whitelist

--serversecure.EnableFirewallBlacklist(boolean) -- enable "firewall" blacklist, any client in the blacklist doesn't see the server
--serversecure.AddBlacklistIP(ip_in_integer_format) -- add an IP to the blacklist
--serversecure.RemoveBlacklistIP(ip_in_integer_format) -- remove an IP from the blacklist
--serversecure.ResetBlacklist() -- reset the blacklist

serversecure.EnableFileValidation(true) -- validates files requested by clients for download

serversecure.EnableThreadedSocket(true) -- receives packets from the game socket on another thread (as well as analyzing it)

serversecure.EnablePacketValidation(true) -- validates packets for having correct types, size, content, etc.

serversecure.EnableInfoCache(true) -- enable A2S_INFO response cache
serversecure.SetInfoCacheTime(5) -- seconds for cache to live (default is 5 seconds)

serversecure.EnableQueryLimiter(true) -- enable query limiter (similar to Source's one but all handled on the same place)
serversecure.SetMaxQueriesWindow(60) -- timespan over which to average query counts from IPs (default is 30 seconds)
serversecure.SetMaxQueriesPerSecond(1) -- maximum queries per second from a single IP (default is 1 per second)
serversecure.SetGlobalMaxQueriesPerSecond(50) -- maximum total queries per second (default is 60 per second)
