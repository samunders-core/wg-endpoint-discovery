-- https://www.jordanwhited.com/posts/wireguard-endpoint-discovery-nat-traversal/
local fm = require "fullmoon"
local re = require "re"
local unix = require "unix"

wg_show_all_dump = "wg show all dump"
wg_show_pattern = re.compile("[^[:space:]]+[[:space:]]+([^[:space:]]+)[[:space:]]+([^[:space:]]+)[[:space:]]+([^[:space:]]+)[[:space:]]+.*")

function get_endpoint(r)
  fd, msg = io.popen(wg_show_all_dump, "r")
  if msg then
    Log(kLogWarn, '%s failed: %s' % {cmd, msg})
    return fm.serveError(500, msg)()
  end
  for line in fd:lines() do
    _, peer, pubkey, endpoint = wg_show_pattern:search(line)
    if endpoint and ({[peer]=true, [pubkey]=true})[r.params.pubkey] then
      fd:close()
      if not endpoint:find(":") then
        for _, adapter in ipairs(unix.siocgifconf()) do
          if adapter.name ~= "lo" and GetServerAddr() ~= adapter.ip then
            endpoint = "%s:%s" % {FormatIp(adapter.ip), endpoint}
            break
          end
        end
      end
      SetHeader('Content-Type', 'text/plain')
      return endpoint
    end
  end
  fd:close()
  return fm.serveError(404, "Peer not seen yet")()
end

function every_minute()
  fd, msg = io.popen(wg_show_all_dump, "r")
  if msg then
    return Log(kLogWarn, '%s failed: %s' % {cmd, msg})
  end
  Log(kLogInfo, "%s succeeded" % {wg_show_all_dump})
  for line in fd:lines() do
    _, pubkey, privkey, endpoint = wg_show_pattern:search(line)
    if pubkey and "(none)" == privkey and endpoint then
      url = "http://%s:%s/endpoint/%s" % {"192.168.254.1", 8080, pubkey}
      status, error, body = Fetch(url)
      if endpoint == body then
        Log(kLogInfo, "Peer %s still at %s" % {pubkey, endpoint})
      elseif status == 200 and body then
        if package.config:sub(1,1) == "\\" then
          -- TODO: win
        else
          cmd = "wg set %s peer %s endpoint %s" % {network, pubkey, body}
          Log(kLogInfo, "executing %s" % {cmd})
          assert(os.execute(cmd) == 0)
        end
      else
        Log(kLogWarn, 'Fetch(%s) failed: %s, %s, %s' % {url, status or "none", error or "", body or ""})
      end
    end
  end
  fd:close()
end

fm.setRoute({"/endpoint/*pubkey", method = "GET"}, get_endpoint)
if not (Slurp("/etc/wireguard/wg0.conf") or ""):find("\nListenPort") then
  fm.setSchedule("* * * * *", every_minute)
end

fm.run()

