-- https://www.jordanwhited.com/posts/wireguard-endpoint-discovery-nat-traversal/
local fm = require "fullmoon"
local inspect = require "inspect"
local re = require "re"
local unix = require "unix"

-- this address is the only configuration "knob"; port can be specified as second argument. But that's it
manager_address = ParseIp(arg[1] or "")

log_buffer_size = 64 * 1024
log_buffer_words = log_buffer_size / 8
log_buffer = unix.mapshared(log_buffer_size + 8) -- +8 is word where ever-increasing logical offset is tracked (reads/writes via modulo)

function log(level, msg)
  Log(level, msg)
  local json = "%s\0" % {EncodeJson({event=tostring(level), data="<li>%s</li>" % {msg}})}
  if #json > log_buffer_size then
    local mark = "(truncated)"
    msg = msg:sub(1, #msg - (#json - log_buffer_size) - #mark)
    json = "%s\0" % {EncodeJson({event=tostring(level), data="<li>%s%s</li>" % {msg, mark}})}
  end
  local count = #json
  local offset = log_buffer:load(log_buffer_words)
  local pos = offset % log_buffer_size
  if #json > log_buffer_size - pos then
    local suffix = json:sub(1 + log_buffer_size - pos)
    log_buffer:write(0, suffix, #suffix)
    count = log_buffer_size - pos
  end
  log_buffer:write(pos, json, count)
  log_buffer:store(log_buffer_words, offset + #json)
  log_buffer:wake(log_buffer_words)
end

function system(cmd)
  log(kLogInfo, "executing %s: %s" % {cmd, inspect(table.pack(os.execute(cmd)), {newline="", indent="  "})})
end

function pid_dir()
  if GetHostOs() ~= "WINDOWS" then
    return "/run"
  end
  for _, var in ipairs(unix.environ()) do
    if var:sub(1, 8) == "APPDATA=" then
      return var:sub(9)
    end
  end
  return "/C/Windows"
end

-- documented .com / .exe suffixing did not work
function which(name)
  local path, msg = unix.commandv(GetHostOs() == "WINDOWS" and ("%s.exe" % {name}) or name)
  if msg then
    log(kLogFatal, "%s lookup failed: %s" % {name, msg})
    unix.exit(1)
  elseif GetHostOs() == "WINDOWS" and path:find(" ") then
    path = "\"%s\"" % {path}
  end
  return path
end

if manager_address == -1 then
  if GetHostOs() == "WINDOWS" and arg[1] == "terminate" then
    system("%s advfirewall firewall delete rule name=redbean_ping" % {which("netsh")})
    pid = Slurp("%s/redbean.pid" % {pid_dir()}) or "-1"
    log(kLogWarn, "Sending SIGINT to %s" % {pid})
    unix.kill(tonumber(pid, 10), unix.SIGINT)
    unix.exit(0)
  end
  log(kLogFatal, "Malformed manager address provided as first argument: %s" % {arg[1] or ""})
  unix.exit(1)
elseif IsDaemon() and GetHostOs() == "WINDOWS" then  -- so it is possible to turn off first redbean by starting second instance with 'terminate' argument
  ProgramPidPath("%s/redbean.pid" % {pid_dir()})
end

wg = which("wg")
wg_show_all_dump = "%s show all dump" % {wg}

NO_SP = "[^[:space:]]+"
SP = "[[:space:]]+"
wg_show_pattern = re.compile("(%s)%s(%s)%s(%s)%s(%s)%s(%s)(%s%s%s(%s)%s.*)?" % {NO_SP, SP, NO_SP, SP, NO_SP, SP, NO_SP, SP, NO_SP, SP, NO_SP, SP, NO_SP, SP})

function logread(r)
  previous_position = r.session.log_position or 0
  local errno = select(2, log_buffer:wait(log_buffer_words, previous_position))
  r.session.log_position = log_buffer:load(log_buffer_words)
  if previous_position == r.session.log_position then
    return "", errno
  end
  previous_position = previous_position % log_buffer_size
  end_position = r.session.log_position % log_buffer_size
  if end_position > previous_position then
   return log_buffer:read(previous_position, end_position - previous_position), errno
  end
  messages = log_buffer:read(previous_position, log_buffer_size - previous_position)
  if end_position > 0 then
    messages = messages .. log_buffer:read(0, end_position)
  end
  return messages, errno
end

function serve_sse(r)
  if r.session.sse == "done" then
    r.session.sse = nil
    fm.logInfo("Stop SSE processing")
    return fm.serveContent("sse", {})
  end
  r.session.sse = "done"
  fm.streamContent("sse", {retry=5000})
  repeat
    local messages, errno = logread(r)
    for msg in messages:gmatch("([^\0]+)\0+") do
      local json, err = DecodeJson(msg)
      if err then
        Log(kLogWarn, "Failed to decode '%s': '%s'" % {inspect(msg), err})
      elseif json then
        fm.streamContent("sse", json)
      end
    end
  until errno and errno:errno() == unix.EINTR
  return fm.serveContent("sse", {})
end

function serve_peers(r)
  local fd, msg = io.popen(wg_show_all_dump, "r")
  if msg then
    log(kLogWarn, "%s failed: %s" % {cmd, msg})
    return fm.serveError(500, msg)()
  end
  SetHeader("Content-Type", "text/plain")
  for line in fd:lines() do
    local _, network, peer, privkey, endpoint, allowed_ips, _, received = wg_show_pattern:search(line)
    if received ~= "0" and privkey == "(none)" and allowed_ips ~= ("%s:%s" % {FormatIp(GetRemoteAddr()), select(2, GetRemoteAddr())}) then
      fm.render("peer", {peer = peer}) 
    end
  end
  fd:close()
  return true
end

function serve_endpoint(r)
  local fd, msg = io.popen(wg_show_all_dump, "r")
  if msg then
    log(kLogWarn, "%s failed: %s" % {cmd, msg})
    return fm.serveError(500, msg)()
  end
  for line in fd:lines() do
    local _, network, peer, pubkey, endpoint, allowed_ips, _, received = wg_show_pattern:search(line)
    if endpoint and not endpoint:find("(none)") and ({[peer]=true, [pubkey]=true})[r.params.pubkey] then
      fd:close()
      if not endpoint:find(":") then
        for _, adapter in ipairs(unix.siocgifconf()) do
          if adapter.name ~= "lo" and GetServerAddr() ~= adapter.ip then
            endpoint = "%s:%s" % {FormatIp(adapter.ip), endpoint}
            break
          end
        end
      end
      SetHeader("Content-Type", "text/plain")
      SetHeader("X-Client-Address", FormatIp(GetRemoteAddr()))
      if allowed_ips:find("/") then
        return "%s allowed-ips %s" % {endpoint, allowed_ips}
      end
      return endpoint
    end
  end
  fd:close()
  return fm.serveError(404, "Peer not seen yet")()
end

function fetch_endpoint(network, pubkey, endpoint)
  local url = fm.makeUrl("", {scheme="http", host=FormatIp(manager_address), port=arg[2] or "8080", path=fm.makePath("/endpoint/*pubkey", {pubkey=pubkey})})
  local status, headers, body = Fetch(url)
  if body and endpoint and endpoint == body:sub(1, #endpoint) then
    log(kLogInfo, "Peer %s still at %s" % {pubkey, endpoint})
    local allowed_ips = body:gsub(".* ([0-9.]+)/32", "%1")
    if headers["X-Client-Address"] ~= allowed_ips then
      return allowed_ips
    end
  elseif status == 200 and body and not body:find("(none)") then
    local allowed_ips = body:gsub(".* ([0-9.]+)/32", "%1")
    if headers["X-Client-Address"] == allowed_ips then
    elseif GetHostOs() == "WINDOWS" then
      system("%s set %s peer %s persistent-keepalive 13 endpoint %s" % {wg, network, pubkey, body})
      system("%s add %s mask 255.255.255.255 %s" % {which("route"), allowed_ips, headers["X-Client-Address"]})
      system("%s advfirewall firewall add rule name=redbean_ping protocol=icmpv4:8,any dir=in localip=%s action=allow" % {which("netsh"), headers["X-Client-Address"]})
      return allowed_ips
    else
      for _, adapter in ipairs(unix.siocgifconf()) do
        if headers["X-Client-Address"] == FormatIp(adapter.ip) then
          system("%s set %s peer %s persistent-keepalive 13 endpoint %s" % {wg, network, pubkey, body})
          system("%s route replace %s dev %s scope link" % {which("ip"), allowed_ips, adapter.name})
          return allowed_ips
        end
      end
    end
  elseif status ~= 404 then
    log(kLogWarn, "Fetch(%s) failed: %s, %s, %s" % {url, status or "none", headers or "", body or ""})
  end
  return ""
end

function ping(addresses)
  addresses[""] = nil
  local fmt = "%s %s" % {which("ping"), GetHostOs() == "WINDOWS" and "/n 3 /w 1000 %s" or "-n -c 3 -i 1 -W 1 %s"}
  for address, _ in pairs(addresses) do
    system(fmt % {address})
  end
end

function every_minute()
  local url = fm.makeUrl("", {scheme="http", host=FormatIp(manager_address), port=arg[2] or "8080", path="peers"})
  local status, error, body = Fetch(url)
  if body and #body > 2 then
    local cmd = "%s show interfaces" % {wg}
    local fd, msg = io.popen(cmd, "r")
    if not msg then
      local ping_targets = {}
      for network in fd:lines() do
        network = network:gsub("\r", "")
        Fetch(fm.makeUrl("", {scheme="http", host=FormatIp(manager_address), port=arg[2] or "8080", path="favicon.ico"})) -- fails in Windows with interrupted syscall
        for pubkey in body:gmatch("([^\r\n]*)[\r\n]*") do
          ping_targets[fetch_endpoint(network, pubkey, nil)] = true
        end
      end
      fd:close()
      return ping(ping_targets)
    end
    log(kLogWarn, "%s failed: %s" % {cmd, msg})
  end
  log(kLogWarn, "Fetch(%s) failed: %s, %s, %s" % {url, status or "none", error or "", body or ""})
  local fd, msg = io.popen(wg_show_all_dump, "r")
  if msg then
    return log(kLogWarn, "%s failed: %s" % {cmd, msg})
  end
  local ping_targets = {}
  for line in fd:lines() do
    local _, network, pubkey, privkey, endpoint, _, _, received = wg_show_pattern:search(line)
    if pubkey and "(none)" == privkey and endpoint then
      log("Received %s from %s" % {received, endpoint})
      ping_targets[fetch_endpoint(network, pubkey, endpoint)] = true
    end
  end
  fd:close()
  ping(ping_targets)
end

for _, adapter in ipairs(unix.siocgifconf()) do
  if manager_address == adapter.ip then
    fm.setTemplate("peer", "{%= peer %}\n")
    fm.setRoute({"/peers", method = "GET"}, serve_peers)
    fm.setRoute({"/endpoint/*pubkey", method = "GET"}, serve_endpoint)
    every_minute = nil
    break
  end
end

if every_minute then
  fm.setSchedule("* * * * *", every_minute)
end

fm.setRoute("/sse", serve_sse)
fm.setRoute("/*", function() return [[
<!DOCTYPE html><html><head>
<script src="https://unpkg.com/htmx.org@1.9.11" ></script>
<script src="https://unpkg.com/htmx.org@1.9.11/dist/ext/sse.js"></script>
</head>
<body><h1>Log</h1>
<ul id="sse" hx-ext="sse" sse-connect="/sse" sse-swap="message,0,1,2,3,4,5,6" hx-swap="beforeend">
</ul></body></html>]]
end)

fm.run()

