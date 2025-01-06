local fm = require "fullmoon"
local inspect = require "inspect"
local lines = require "lines"
local log = require "log"
local sqlite3 = require 'lsqlite3'
local system = require "system"
local which = system.which

-- this address is the only configuration "knob"; port can be specified as second argument. But that's it
manager_address = ParseIp(arg[1] or "")
ProgramTimeout(3000) -- to limit duration of Fetch("/statusz") via VPN

if manager_address == -1 then
	if GetHostOs() == "WINDOWS" then
		if arg[1] == "terminate" then
			system("%s advfirewall firewall delete rule name=redbean_statusz" % { which("netsh") })
			pid = Slurp("%s/redbean.pid" % { system.pid_dir() }) or "-1"
			log(kLogWarn, "Sending SIGINT to %s" % { pid })
			unix.kill(tonumber(pid, 10), unix.SIGINT)
			unix.exit(0)
		elseif not which("wg", "ignore_not_found") then
			local status, headers, body = Fetch("https://download.wireguard.com/windows-client/wireguard-installer.exe")
			log(status and kLogInfo or kLogWarn, "Fetch(%s) %s: %s" % { url, status or "failed", headers or "" })
			if body then
				for _, dir in ipairs({ path.dirname(unix.realpath(arg[-1])), home_dir() }) do -- TODO: home_dir()
					file = path.join(dir, headers["filename"] or "wireguard_installer.exe")
					local _, msg = Barf(file, body)
					if not msg then
						system(file)
						break
					end
					log(kLogWarn, "Failed to save wiregard installer to %s directory: %s" % { dir, msg })
				end
			end
			-- TODO: start configuration wizard
		end
	elseif GetHostOs() == "LINUX" and not which("wg", "ignore_not_found") then
		-- TODO https://superuser.com/questions/287371/how-to-obtain-kernel-config-from-currently-running-linux-system
		for _, cmd in ipairs({ "apt-get", "dnf" }) do
			cmd = which(cmd, "ignore_not_found")
			if cmd then
				system("%s --yes install wireguard" % { cmd })
			end
		end
	end
	log(kLogFatal, "Malformed manager address provided as first argument: %s" % { arg[1] or "" })
	unix.exit(1)
elseif IsDaemon() and GetHostOs() == "WINDOWS" then -- so it is possible to turn off first redbean by starting second instance with 'terminate' argument
	ProgramPidPath("%s/redbean.pid" % { system.pid_dir() })
end

wg = which("wg")
wg_show_all_dump = "%s show all dump" % { wg }
wg_show_pattern = ("(network+)%s+(peer+)%s+(key+)%s+(endpoint+)%s+(allowed_ips+)%s*(hands_shaken_at*)%s*(received*)%s*.*")
	:gsub("[_%w][_%w]+", "%%S")
ports = {}
db = manager_address ~= -1 and
fm.makeStorage(":memory:", [[ CREATE TABLE ping_failures(address TEXT PRIMARY KEY, count INTEGER NOT NULL); ]])


function OnServerListen(socketdescriptor, serverip, serverport)
	ports[#ports] = serverport -- collect ports given by -p command line switch
end

function serve_online_peers(r)
	local json = (r.headers.Accept or ""):find("/json") and {}
	SetHeader("Content-Type", json and "application/json" or "text/plain")
	SetHeader("X-Client-Address", FormatIp(GetRemoteAddr()))
	local output = lines(wg_show_all_dump)
	for _, line in ipairs(output) do
		local _, _, network, peer, privkey, endpoint, allowed_ips, hands_shaken_at, received = line:find(wg_show_pattern)
		log(kLogInfo, inspect({ line, network, peer, privkey, endpoint, allowed_ips, hands_shaken_at, received }))
		if received ~= "0" and privkey == "(none)" and allowed_ips ~= ("%s:%s" % { FormatIp(GetRemoteAddr()), select(2, GetRemoteAddr()) }) then
			if json then
				table.insert(json, peer)
			else
				fm.render("peer", { ["peer"] = peer })
			end
		end
	end
	if json then
		SetStatus(output.failure and 500 or 200)
		return fm.serveContent("json", json or { error = output.failure })
	end
	return not output.failure or fm.serveError(500, output.failure)()
end

function serve_endpoint(r)
	local output = lines(wg_show_all_dump)
	for _, line in ipairs(output) do
		local _, _, network, peer, pubkey, endpoint, allowed_ips, hands_shaken_at, received = line:find(wg_show_pattern)
		if endpoint and not endpoint:find("(none)") and ({ [peer] = true, [pubkey] = true })[r.params.pubkey] then
			if not endpoint:find(":") then
				endpoint = "%s:%s" % { FormatIp(system.network_adapter { without = GetServerAddr() }.ip), endpoint }
			end
			local json = (r.headers.Accept or ""):find("/json") and { endpoint = endpoint }
			SetHeader("Content-Type", json and "application/json" or "text/plain")
			SetHeader("X-Client-Address", FormatIp(GetRemoteAddr()))
			local result = endpoint
			if allowed_ips:find("/") then
				if json then
					json["allowed_ips"] = allowed_ips
				end
				result = "%s allowed-ips %s # latest-handshake=%s" % { endpoint, allowed_ips, hands_shaken_at }
			end
			if json and hands_shaken_at ~= "" then
				json["hands_shaken_at"] = hands_shaken_at
			end
			return json and fm.serveContent("json", json) or result
		end
	end
	if (r.headers.Accept or ""):find("/json") then
		SetStatus(output.failure and 500 or 404)
		return fm.serveContent("json", { error = output.failure or "Peer not seen yet" })
	end
	return fm.serveError(output.failure and 500 or 404, output.failure or "Peer not seen yet")()
end

function log_transfers(network, pubkey)
	for _, line in ipairs(lines("%s show %s transfer" % { wg, network })) do
		if line:find(pubkey) then
			log(kLogInfo, "%s bytes sent" % { line:sub(1 + #pubkey + 1):gsub("%s", " bytes received, ", 1) })
		end
	end
end

function make_url(path, address, port, scheme)
	return fm.makeUrl("",
		{
			scheme = scheme or "http",
			host = type(address) == "number" and FormatIp(address) or address,
			port = port or arg[2] or "8080",
			path = path
		})
end

function fetch_endpoint(network, pubkey, endpoint, hands_shaken_at)
	local url = make_url(fm.makePath("/endpoint/*pubkey", { pubkey = pubkey }), manager_address)
	local status, headers, body = Fetch(url, { method = "GET", headers = { Accept = "application/json" } })
	body = DecodeJson((body or ""):gsub("^%s*$", "null"))
	if type(body) == "table" and endpoint and endpoint == (body["endpoint"] or ""):sub(1, #endpoint) then
		log(kLogInfo, "Peer %s still at %s" % { pubkey, endpoint })
		local allowed_ips = (body["allowed_ips"] or ""):gsub("/%d+", "")
		if headers["X-Client-Address"] ~= allowed_ips then
			hands_shaken_at[allowed_ips] = body["hands_shaken_at"] or tostring(GetDate())
		end
	elseif status == 200 and type(body) == "table" and not (body["endpoint"] or "(none)"):find("(none)") then
		local allowed_ips = (body["allowed_ips"] or ""):gsub("/%d+", "")
		endpoint = allowed_ips == "" and body["endpoint"] or "%s allowed_ips %s" % { body["endpoint"], allowed_ips }
		if headers["X-Client-Address"] == allowed_ips then
			-- TODO: allow data info about peers that cannot reach us
			log(kLogInfo, inspect({ ignored = body }, { newline = "", indent = "  " }))
		elseif GetHostOs() == "WINDOWS" then
			system("%s set %s peer %s persistent-keepalive 13 endpoint %s" % { wg, network, pubkey, endpoint })
			system("%s add %s mask 255.255.255.255 %s" % { which("route"), allowed_ips, headers["X-Client-Address"] })
			system(
				"%s advfirewall firewall add rule name=redbean_statusz protocol=tcp dir=in localip=%s localport=%s action=allow" %
				{ which("netsh"), headers["X-Client-Address"], arg[2] or "8080" })
			log_transfers(network, pubkey)
			hands_shaken_at[allowed_ips] = body["hands_shaken_at"] or tostring(GetDate())
		else
			adapter = system.network_adapter(headers["X-Client-Address"])
			if adapter.ip then
				system("%s set %s peer %s persistent-keepalive 13 endpoint %s" % { wg, network, pubkey, endpoint })
				system("%s route replace %s dev %s scope link" % { which("ip"), allowed_ips, adapter.name })
				log_transfers(network, pubkey)
				hands_shaken_at[allowed_ips] = body["hands_shaken_at"] or tostring(GetDate())
			end
		end
	elseif status ~= 404 then
		log(status and kLogInfo or kLogWarn, "Fetch(%s) %s: %s" % { url, status or "failed", body or headers or "" })
	end
end

function ping(addresses)
	addresses[""] = nil -- do not treat results of failed Fetch-es as address
	local result = {}
	for address, hands_shaken_at in pairs(addresses) do
		local now = GetDate()
		local url = make_url("statusz", address)
		local status, error, body = Fetch(url)
		result[address] = "Fetch(%s) %s: %s" % { url, status or "failed", body or error or "" }
		if status then
			local row, error = db:fetchOne(
				[[ DELETE FROM ping_failures WHERE address = ?1 RETURNING count; ]], address
			)
			if error then
				result[address] = "%s\n%s" % { result[address], error }
			elseif row["count"] then
				result[address] = "%s\nConnection restored after %s attempts" % { result[address], row["count"] }
			end
		else
			local row, error = db:fetchOne([[
					INSERT INTO ping_failures(address, count) VALUES(?1, 1)
					ON CONFLICT(address) DO UPDATE SET count=count+1
					RETURNING count;
				]], address
			)
			if error or row["count"] <= 4 or 180 < now - hands_shaken_at then
				result[address] = "%s%s%s" % {
					error and result[address] or row["count"],
					error and "\n" or "x since %s: " % { FormatHttpDateTime(hands_shaken_at) },
					error or result[address]
				}
			elseif GetHostOs() == "WINDOWS" then -- we're in grandchild of restarted process
				result[address] = "Ping to %s failed repeatedly, restating VPN client" % { address }
				system(
					[[schtasks /create /tn "Restart wg" /tr '%s -command "Restart-Service %s -Force"' /sc once /st 00:00:03 /ru "SYSTEM"]]
					% { which("powershell"), "WireGuardTunnel$my-tunnel" }
				)
				-- https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/sc-query
				--system("Start-Process sc.exe -ArgumentList 'config', 'WireGuardTunnel$my-tunnel', 'start= delayed-auto' -Wait -NoNewWindow -PassThru | Out-Null")
			end
		end
	end
	return inspect(result, { newline = "", indent = "  " })
end

function serve_ping_peers(r) -- every ${ARG3:-13000} millis, already in child process
	SetHeader("Content-Type", "text/plain")
	local ping_targets = {}
	local url = make_url("online-peers", manager_address)
	local status, headers, body = Fetch(url)
	if body and #body > 2 then
		local output = lines("%s show interfaces" % { wg })
		-- log(kLogInfo, inspect({body=body, output=output}, { newline = "", indent = "  " }))
		for _, network in ipairs(output) do
			for pubkey in body:gmatch("([^\r\n]*)[\r\n]*") do
				fetch_endpoint(network, pubkey, nil, ping_targets)
			end
		end
		if ping_targets or not output.failure then
			return ping(ping_targets)
		end
	else
		log(status and kLogInfo or kLogWarn, "Fetch(%s) %s: %s" % { url, status or "failed", body or headers or "" })
	end
	for _, line in ipairs(lines(wg_show_all_dump)) do
		local _, _, network, pubkey, privkey, endpoint, allowed_ips, hands_shaken_at, received = line:find(
			wg_show_pattern)
		if pubkey and "(none)" == privkey and endpoint then
			log("Received %s from %s" % { received, endpoint })
			fetch_endpoint(network, pubkey, endpoint, ping_targets)
		end
	end
	return ping(ping_targets)
end

function OnServerHeartbeat()      -- every ${ARG3:-13000} millis
	local url = make_url("ping-peers", "127.0.0.1", ports[#ports])
	if assert(unix.fork()) == 0 then -- Fetch blocks
		local status, error, body = Fetch(url)
		log(status and kLogInfo or kLogWarn, "Fetch(%s) %s: %s" % { url, status or "failed", body or error or "" })
	end
end

if (system.network_adapter { with = manager_address }).ip then
	fm.setTemplate("peer", "{%= peer %}\n")
	fm.setRoute({ "/online-peers", method = "GET" }, serve_online_peers)
	fm.setRoute({ "/endpoint/*pubkey", method = "GET" }, serve_endpoint)
	log(kLogInfo, "Manager at %s needs no heartbeat handler, clearing it" % { FormatIp(manager_address) })
	OnServerHeartbeat = nil
else
	fm.setRoute({ "/ping-peers", method = "GET" }, serve_ping_peers)
end

--SetLogLevel(kLogDebug)
fm.setRoute({ "/statusz", method = "GET" }, function(r) return ServeStatusz() or "" end)
--[[fm.setRoute("/sse", log.serve_sse)
fm.setRoute("/*", function(r)
	return [[
<!DOCTYPE html><html><head>
<script src="https://unpkg.com/htmx.org@1.9.11" ></script>
<script src="https://unpkg.com/htmx.org@1.9.11/dist/ext/sse.js"></script>
</head>
<body><h1>Log</h1>
<ul id="sse" hx-ext="sse" sse-connect="/sse" sse-swap="message,0,1,2,3,4,5,6" hx-swap="beforeend">
</ul></body></html>]]
--end)

if OnServerHeartbeat then
	ProgramHeartbeatInterval(arg[3] or 13000)
	LaunchBrowser("/log")
end

fm.run()
