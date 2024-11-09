local lines = {}
lines._DESCRIPTION = 'Slurp command output lines into table'

local log = require "log"

function lines.popen(cmd)
  local fd, msg = io.popen(cmd, "r")
  if not fd then
    log(kLogWarn, "%s failed: %s" % { cmd, msg or "" })
    return { failure = msg }
  end
  local result = {}
  for line in fd:lines() do
    line, _ = line:gsub("\r", "")
    table.insert(result, line)
  end
  fd:close()
  log(kLogInfo, "%s success: %s lines" % { cmd, #result })
  return result
end

setmetatable(lines, {
  __call = function(_, cmd)
    return lines.popen(cmd)
  end,
})

return lines
