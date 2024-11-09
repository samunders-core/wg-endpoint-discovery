local log = {}
log._DESCRIPTION = 'log pipe to browser over SSE'

local fm = require "fullmoon"
local inspect = require "inspect"
local unix = require "unix"

local log_buffer_size = 64 * 1024
local log_buffer_words = log_buffer_size / 8
local log_buffer = unix.mapshared(log_buffer_size + 8) -- +8 is word where ever-increasing logical offset is tracked (reads/writes via modulo)

function log.read(r)
  local previous_position = r.session.log_position or 0
  local errno = select(2, log_buffer:wait(log_buffer_words, previous_position))
  r.session.log_position = log_buffer:load(log_buffer_words)
  if previous_position == r.session.log_position then
    return "", errno
  end
  previous_position = previous_position % log_buffer_size
  local end_position = r.session.log_position % log_buffer_size
  if end_position > previous_position then
    return log_buffer:read(previous_position, end_position - previous_position), errno
  end
  local messages = log_buffer:read(previous_position, log_buffer_size - previous_position)
  if end_position > 0 then
    messages = messages .. log_buffer:read(0, end_position)
  end
  return messages, errno
end

function log.log(level, msg)
  Log(level, msg)
  local json = "%s\0" % { EncodeJson({ event = tostring(level), data = "<li>%s</li>" % { msg } }) }
  if #json > log_buffer_size then
    local mark = "(truncated)"
    msg = msg:sub(1, #msg - (#json - log_buffer_size) - #mark)
    json = "%s\0" % { EncodeJson({ event = tostring(level), data = "<li>%s%s</li>" % { msg, mark } }) }
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

function log.serve_sse(r)
  if r.session.sse == "done" then
    r.session.sse = nil
    fm.logInfo("Stop SSE processing")
    return fm.serveContent("sse", {})
  end
  r.session.sse = "done"
  fm.streamContent("sse", { retry = 5000 })
  repeat
    local messages, errno = log.read(r)
    for msg in messages:gmatch("([^\0]+)\0+") do
      local json, err = DecodeJson(msg)
      if err then
        log.log(kLogWarn, "Failed to decode '%s': '%s'" % { inspect(msg), err })
      elseif json then
        fm.streamContent("sse", json)
      end
    end
  until errno and errno:errno() == unix.EINTR
  return fm.serveContent("sse", {})
end

setmetatable(log, {
  __call = function(_, level, msg)
    return log.log(level, msg)
  end,
})

return log
