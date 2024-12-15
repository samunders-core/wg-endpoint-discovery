-- https://www.jordanwhited.com/posts/wireguard-endpoint-discovery-nat-traversal/
local fm = require "fullmoon"
local inspect = require "inspect"
local lines = require "lines"
local log = require "log"
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
	end
	log(kLogFatal, "Malformed manager address provided as first argument: %s" % { arg[1] or "" })
	unix.exit(1)
elseif IsDaemon() and GetHostOs() == "WINDOWS" then -- so it is possible to turn off first redbean by starting second instance with 'terminate' argument
	ProgramPidPath("%s/redbean.pid" % { system.pid_dir() })
end

wg = which("wg")
wg_show_all_dump = "%s show all dump" % { wg }

NO_SP = "[^[:space:]]+"
SP = "[[:space:]]+"
wg_show_pattern = re.compile("(%s)%s(%s)%s(%s)%s(%s)%s(%s)(%s%s%s(%s)%s.*)?" %
	{ NO_SP, SP, NO_SP, SP, NO_SP, SP, NO_SP, SP, NO_SP, SP, NO_SP, SP, NO_SP, SP })
ports = {}

function OnServerListen(socketdescriptor, serverip, serverport)
	ports[#ports] = serverport  -- collect ports given by -p command line switch
end

function serve_online_peers(r)
	SetHeader("Content-Type", "text/plain")
	output = lines(wg_show_all_dump)
	for _, line in ipairs(output) do
		local _, network, peer_, privkey, endpoint, allowed_ips, _, received = wg_show_pattern:search(line)
		if received ~= "0" and privkey == "(none)" and allowed_ips ~= ("%s:%s" % { FormatIp(GetRemoteAddr()), select(2, GetRemoteAddr()) }) then
			fm.render("peer", { peer = peer_ })
		end
	end
	return not output.failure or fm.serveError(500, output.failure)()
end

function serve_endpoint(r)
	output = lines(wg_show_all_dump)
	for _, line in ipairs(output) do
		local _, network, peer, pubkey, endpoint, allowed_ips, _, received = wg_show_pattern:search(line)
		if endpoint and not endpoint:find("(none)") and ({ [peer] = true, [pubkey] = true })[r.params.pubkey] then
			if not endpoint:find(":") then
				endpoint = "%s:%s" % { FormatIp(system.network_adapter { without = GetServerAddr() }.ip), endpoint }
			end
			SetHeader("Content-Type", "text/plain")
			SetHeader("X-Client-Address", FormatIp(GetRemoteAddr()))
			if allowed_ips:find("/") then
				return "%s allowed-ips %s" % { endpoint, allowed_ips }
			end
			return endpoint
		end
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

function fetch_endpoint(network, pubkey, endpoint)
	local url = make_url(fm.makePath("/endpoint/*pubkey", { pubkey = pubkey }), manager_address)
	local status, headers, body = Fetch(url)
	if body and endpoint and endpoint == body:sub(1, #endpoint) then
		log(kLogInfo, "Peer %s still at %s" % { pubkey, endpoint })
		local allowed_ips = body:gsub(".* ([0-9.]+)/32", "%1")
		if headers["X-Client-Address"] ~= allowed_ips then
			return allowed_ips
		end
	elseif status == 200 and body and not body:find("(none)") then
		local allowed_ips = body:gsub(".* ([0-9.]+)/32", "%1")
		if headers["X-Client-Address"] == allowed_ips then
			log(kLogInfo, inspect({ignored=body}, { newline = "", indent = "  " }))
		elseif GetHostOs() == "WINDOWS" then
			system("%s set %s peer %s persistent-keepalive 13 endpoint %s" % { wg, network, pubkey, body })
			system("%s add %s mask 255.255.255.255 %s" % { which("route"), allowed_ips, headers["X-Client-Address"] })
			system(
				"%s advfirewall firewall add rule name=redbean_statusz protocol=tcp dir=in localip=%s localport=%s action=allow" %
				{ which("netsh"), headers["X-Client-Address"], arg[2] or "8080" })
			log_transfers(network, pubkey)
			return allowed_ips
		else
			adapter = system.network_adapter(headers["X-Client-Address"])
			if adapter.ip then
				system("%s set %s peer %s persistent-keepalive 13 endpoint %s" % { wg, network, pubkey, body })
				system("%s route replace %s dev %s scope link" % { which("ip"), allowed_ips, adapter.name })
				log_transfers(network, pubkey)
				return allowed_ips
			end
		end
	elseif status ~= 404 then
		log(status and kLogInfo or kLogWarn, "Fetch(%s) %s: %s" % { url, status or "failed", body or headers or "" })
	end
	return ""
end

function ping(addresses)
	addresses[""] = nil -- do not treat results of failed Fetch-es as address
	result = {}
	for address, _ in pairs(addresses) do
		local url = make_url("statusz", address)
		local status, error, body = Fetch(url)
		result[address] = "Fetch(%s) %s: %s" % { url, status or "failed", body or error or "" }
	end
	return inspect(result, { newline = "", indent = "  " })
end

function serve_ping_peers(r) -- every ${ARG3:-13000} millis, already in child process
	SetHeader("Content-Type", "text/plain")
	local ping_targets = {}
	local url = make_url("online-peers", manager_address)
	local status, error, body = Fetch(url)
	if body and #body > 2 then
		local output = lines("%s show interfaces" % { wg })
		-- log(kLogInfo, inspect({body=body, output=output}, { newline = "", indent = "  " }))
		for _, network in ipairs(output) do
			for pubkey in body:gmatch("([^\r\n]*)[\r\n]*") do
				ping_targets[fetch_endpoint(network, pubkey, nil)] = true
			end
		end
		if ping_targets or not output.failure then
			return ping(ping_targets)
		end
	else
		log(status and kLogInfo or kLogWarn, "Fetch(%s) %s: %s" % { url, status or "failed", body or error or "" })
	end
	for _, line in ipairs(lines(wg_show_all_dump)) do
		local _, network, pubkey, privkey, endpoint, _, _, received = wg_show_pattern:search(line)
		if pubkey and "(none)" == privkey and endpoint then
			log("Received %s from %s" % { received, endpoint })
			ping_targets[fetch_endpoint(network, pubkey, endpoint)] = true
		end
	end
	return ping(ping_targets)
end

function OnServerHeartbeat() -- every ${ARG3:-13000} millis
	local url = make_url("ping-peers", "127.0.0.1", ports[#ports])
	if assert(unix.fork()) == 0 then  -- Fetch blocks
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
