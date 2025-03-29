local fm = require "fullmoon"
local inspect = require "inspect"
local lines = require "lines"
local log = require "log"
local system = require "system"
local which = system.which

-- this address is the only configuration "knob"; VPN restarting can be allowed with second argument. But that's it
manager_address = ParseIp(arg[1] or "")
ProgramTimeout(3000) -- to limit duration of Fetch("/healthcheck") via VPN

if manager_address == -1 then
	if GetHostOs() == "WINDOWS" then
		if arg[1] == "terminate" then
			system("%s advfirewall firewall delete rule name=redbean_healthcheck" % { which("netsh") })
			pid = Slurp("%s/redbean.pid" % { system.pid_dir() }) or "-1"
			log(kLogWarn, "Sending SIGINT to %s" % { pid })
			unix.kill(tonumber(pid, 10), unix.SIGINT)
			unix.exit(0)
		elseif not which("wg", "ignore_not_found") then
			local status, headers, body = Fetch("https://download.wireguard.com/windows-client/wireguard-installer.exe")
			log(status and kLogInfo or kLogWarn, "Fetch(%s) %s: %s" % { url, status or "failed", headers or "" })
			if body then
				for _, dir in ipairs({ path.dirname(unix.realpath(arg[-1])), system.pid_dir(), system.home_dir() }) do
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
network = lines("%s show interfaces" % { wg })[1]
restart_heartbeats = 3
db_file_path = nil

function makeStorage()
	for _, dir in ipairs({ path.dirname(unix.realpath(arg[-1])), system.pid_dir(), system.home_dir(), "." }) do
		db_file_path = system.env("DB_PATH", "%s/redbean.counts.sqlite3" % { dir })
		local status, db = pcall(fm.makeStorage, db_file_path, -- :memory: does not work because forks don't share it
			[[ CREATE TABLE counts(key TEXT PRIMARY KEY, count INTEGER NOT NULL); ]], {
				trace = function(_, ...) log(kLogDebug, inspect({ ... })) end
			}
		)
		if status then
			return db
		end
		log(kLogWarn, db)
	end
	unix.exit(1)
end

db = makeStorage()

function OnServerStop()
	if db_file_path then
		unix.unlink(db_file_path)
	end
end

function peer(line, received_condition)
	local _, _, network, peer, privkey, endpoint, allowed_ips, hands_shaken_at, received = line:find(
		wg_show_pattern)
	log(kLogInfo, inspect({ line, network, peer, privkey, endpoint, allowed_ips, hands_shaken_at, received }))
	if privkey ~= "(none)" or not received_condition(received) then
		return nil
	end
	return { ["pubkey"] = peer, ["endpoint"] = endpoint, ["allowed_ips"] = allowed_ips }
end

function is_unknown_peer(candidate)
	for range in candidate["allowed_ips"]:gmatch("([0-9./:]*)") do
		if range:find(FormatIp(GetRemoteAddr()) .. "/") == 1 or range:find(FormatIp(GetServerAddr()) .. "/") == 1 then
			return nil
		end
	end
	return candidate
end

function serve_other_online_peers(r)
	local result = { [0] = false } -- serialize "empty" as array
	local _, error = db:fetchOne([[ DELETE FROM counts WHERE key = ?1; ]], FormatIp(GetRemoteAddr()))
	if not error then
		local output = lines(wg_show_all_dump)
		for _, line in ipairs(output) do
			candidate = peer(line, function(received) return received ~= "0" end)
			candidate = candidate and is_unknown_peer(candidate)
			if candidate then
				table.insert(result, candidate)
			end
		end
		error = output.failure
	end
	SetStatus(error and 500 or 200)
	r.headers["X-Client-Address"] = FormatIp(GetRemoteAddr()) -- SetHeader was ignored
	return fm.serveContent("json", error and { error = error } or result)
end

function make_url(path, address, port, scheme)
	return fm.makeUrl("",
		{
			scheme = scheme or "http",
			host = type(address) == "number" and FormatIp(address) or address,
			port = port or ports[#ports] or "8080",
			path = path
		})
end

function serve_notify(r) -- this is /notify/C @ B, A is the client and C is the destination host
	local url = make_url(fm.makePath("/failed/:address", { address = FormatIp(GetRemoteAddr()) }), r.params.address)
	local status, error, body = Fetch(url, { method = "POST", headers = { Accept = "application/json" } })
	SetStatus(status or 502)
	if status then
		return body or ""
	end
	return fm.serveContent("json", { error = "Fetch(%s) failed: %s" % { url, error } })
end

function serve_failed(r) -- this is /failed/A @ C, B is the client and A is the origin host who was not able to reach us
	local row, error = db:fetchOne([[
			INSERT INTO counts(key, count) VALUES(?1, 1)
			ON CONFLICT(key) DO UPDATE SET count=count+1
			RETURNING count;
		]], r.params.address or "healthcheck"
	)
	if not error and not r.params.address then
		_, error = db:fetchOne([[ DELETE FROM counts WHERE key = ?1; ]], FormatIp(GetRemoteAddr()))
	end
	SetStatus(error and 500 or 200)
	r.headers["X-Client-Address"] = FormatIp(GetRemoteAddr())
	return fm.serveContent("json", error and { error = error } or { count = row["count"] })
end

function restart_vpn()
	local row, error = db:fetchOne(
		[[ SELECT key, count FROM counts WHERE key <> ?1 ORDER BY count DESC LIMIT 1; ]], "healthcheck")
	if error then
		return log(kLogError, error)
	elseif not row["count"] or row["count"] < 3 or not arg[2] then
		return
	elseif GetHostOs() == "WINDOWS" then -- we're in grandchild of restarted process
		log(kLogWarn, "Ping from %s failed %s times, restating VPN client" % { row["address"], row["count"] })
		system(
			[[schtasks /create /tn "Restart wg" /tr '%s -command "Restart-Service %s -Force"' /sc once /st 00:00:03 /ru "SYSTEM"]]
			% { which("powershell"), "WireGuardTunnel$my-tunnel" }
		)
		-- https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/sc-query
		--system("Start-Process sc.exe -ArgumentList 'config', 'WireGuardTunnel$my-tunnel', 'start= delayed-auto' -Wait -NoNewWindow -PassThru | Out-Null")
		local _, error = db:fetchOne([[ DELETE FROM counts WHERE key <> ?1; ]], "healthcheck")
		log(error and kLogWarn or kLogInfo, error or "Ping counts cleared")
	else
		log(kLogInfo, "Ping from %s failed %s times" % { row["address"], row["count"] })
	end
end

function log_transfers(network, pubkey)
	for _, line in ipairs(lines("%s show %s transfer" % { wg, network })) do
		if line:find(pubkey) then
			log(kLogInfo, "%s bytes sent" % { line:sub(1 + #pubkey + 1):gsub("%s", " bytes received, ", 1) })
		end
	end
end

function add_endpoint_address(pubkey, endpoint, allowed_ips, local_address)
	-- TODO: only absent
	for range in allowed_ips:gmatch("([0-9./:]*)") do
		if range:find(local_address .. "/") == 1 then
			return log(kLogInfo,
				inspect({ pubkey, endpoint, allowed_ips, local_address, ignored = true }, { newline = "", indent = "  " }))
		end
	end
	endpoint = "%s allowed-ips %s" % { endpoint, allowed_ips }
	if GetHostOs() == "WINDOWS" then
		system("%s set %s peer %s persistent-keepalive 13 endpoint %s" % { wg, network, pubkey, endpoint })
		system("%s add %s mask 255.255.255.255 %s" % { which("route"), allowed_ips:gsub("/%d+", ""), local_address })
		system(
			"%s advfirewall firewall add rule name=redbean_healthcheck protocol=tcp dir=in localip=%s localport=%s action=allow" %
			{ which("netsh"), local_address, ports[#ports] or "8080" })
		log_transfers(network, pubkey)
	else
		adapter = system.network_adapter(local_address)
		if adapter.ip then
			system("%s set %s peer %s persistent-keepalive 13 endpoint %s" % { wg, network, pubkey, endpoint })
			system("%s route replace %s dev %s scope link" % { which("ip"), allowed_ips:gsub("/%d+", ""), adapter.name })
			log_transfers(network, pubkey)
		end
	end
end

function fetch(address, path, method)
	local url = make_url(path, address)
	local status, error_or_headers, body = Fetch(url,
		{ method = method or "GET", headers = { Accept = "application/json,text/html;q=0.9" } })
	log(status and kLogInfo or kLogWarn, "Fetch(%s) %s: %s" % { url, status or "failed", body or error_or_headers or "" })
	return status, error_or_headers, body
end

function get_online_peers(address) -- every HEARTBEAT_SECONDS, already in child process
	local status, error_or_headers, body = fetch(address, "other-online-peers")
	if not status then
		return {}
	end
	local online_peers, error = DecodeJson(body)
	if type(online_peers) ~= "table" then
		online_peers = {
			error = "%s from '%s'" %
				{ error or "Expected table instead of %s" % { type(online_peers) }, body }
		}
	end
	if online_peers["error"] then
		return log(kLogWarn, online_peers["error"]) or {}
	end
	return online_peers, error_or_headers["X-Client-Address"]
end

function OnServerHeartbeat() -- every HEARTBEAT_SECONDS, already in child process
	local gateway = FormatIp(manager_address)
	local online_peers, local_address = get_online_peers(FormatIp(manager_address))
	if not local_address then
		local output = lines(wg_show_all_dump)
		for _, line in ipairs(output) do
			candidate = peer(line, function(received) return true end)
			if candidate then
				table.insert(online_peers, candidate)
			end
		end
		if output.failure then
			log(kLogError, output.failure)
		end
	end
	for _, peer in ipairs(online_peers) do
		if local_address then
			add_endpoint_address(peer["pubkey"], peer["endpoint"], peer["allowed_ips"], local_address)
		end
		if assert(unix.fork()) == 0 then
			local status, headers = fetch(peer["allowed_ips"]:gsub("/%d+", ""), "healthcheck")
			if not local_address then
				gateway = peer["allowed_ips"]:gsub("/%d+", "")
				local_address = headers["X-Client-Address"]
			elseif not status or status ~= 200 then
				local notify_address = fm.makePath("/notify/:address", { address = local_address })
				fetch(gateway, notify_address, "POST")
			end
			unix.exit(0)
		end
	end
	restart_heartbeats = restart_heartbeats - 1
	if restart_heartbeats < 0 then
		restart_heartbeats = 3
		restart_vpn()
	end
end

function register_routes()
	fm.setRoute({ "/other-online-peers", method = "GET" }, serve_other_online_peers)
	fm.setRoute({ "/notify/:address", method = "POST" }, serve_notify)
	fm.setRoute({ "/failed/:address", method = "POST" }, serve_failed)
	fm.setRoute({ "/healthcheck", method = "GET" }, serve_failed)
	fm.setRoute({ "/config", method = "GET" }, fm.serveContent(
		"cgi",
		GetHostOs() == "WINDOWS" and {
			[[c:\windows\system32\cmd.exe]], "for /f %x in ('"..wg.." show interfaces') do "..wg.." showconf %x"
		} or {
			"/bin/sh", "-c", "%s showconf $(%s show interfaces) | sed -re '/PrivateKey/s|=.*|= <REDACTED>|'" % { wg, wg }
		}
	))
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

	fm.sessionOptions.secret = false  -- prevent `applied random session secret` log message
	fm.run()
end

SetLogLevel(kLogDebug)

if (system.network_adapter { with = manager_address }).ip then
	log(kLogInfo, "Manager at %s needs no heartbeat handler, clearing it" % { FormatIp(manager_address) })
	OnServerHeartbeat = nil
	register_routes()
elseif assert(unix.fork()) ~= 0 then
	log(kLogInfo, "Main PID needs no heartbeat handler, clearing it")
	OnServerHeartbeat = nil
	register_routes()
	--LaunchBrowser("/log")
else  -- each Fetch blocks until timeout or response
	ProgramHeartbeatInterval(tonumber(system.env("HEARTBEAT_SECONDS", "3"), 10) * 1000)
end

function OnServerListen(socketdescriptor, serverip, serverport)
	table.insert(ports, tostring(serverport))  -- collect ports given by -p command line switch
	return OnServerHeartbeat  -- forks won't listen
end
