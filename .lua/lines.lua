local lines = {}
lines._DESCRIPTION = 'Slurp command output lines into table'

local log = require "log"

function lines.popen(cmd)
  -- TODO: execute pipeline if cmd is table
  local fd, msg = io.popen(cmd, "r")
  local result = {}
  if fd then
    for line in fd:lines("l") do
      if line:sub(#line) == '\r' then
        line = line:sub(1, #line - 1)
      end
      table.insert(result, line)
    end
    local success, exitcode, code = fd:close()
    if not success then
      msg = "%s %s" % { exitcode, code }
    end
  end
  log(msg and kLogWarn or kLogInfo, "%s (%s): %s lines" % { cmd, msg or "", #result })
  if msg then
    result["failure"] = msg
  end
  return result
end

setmetatable(lines, {
  __call = function(_, cmd)
    return lines.popen(cmd)
  end,
})

return lines
