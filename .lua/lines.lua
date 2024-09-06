lines = {}
lines._DESCRIPTION = 'Slurp command output lines into table'

local log = require "log"

function lines.popen(cmd)
  local fd, msg = io.popen(cmd, "r")
  if msg then
    log(kLogWarn, "%s failed: %s" % {cmd, msg})
    return {failure=msg}
  end
  result = {}
  for line in fd:lines() do
    table.insert(result, line:gsub("\r", ""))
  end
  fd:close()
  log(kLogInfo, "%s success: %s lines" % {cmd, #result})
  return result
end

setmetatable(lines, {
   __call = function(_, cmd)
      return lines.popen(cmd)
   end,
})

return lines
