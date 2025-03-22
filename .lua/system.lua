local system = {}
system._DESCRIPTION = 'Utility functions extracting runtime environment properties'

local inspect = require "inspect"
local lines = require "lines"
local log = require "log"

function system.env(name, default)
	for _, var in ipairs(unix.environ()) do
		if var:sub(1, #name + 1) == name .. "=" then
			return var:sub(#name + 2)
		end
	end
	return default
end

function system.home_dir()
	result = system.env("HOME")
	if not result then
		result = lines(GetHostOs() == "WINDOWS" and "FIXME" or "id -nu %s" % { unix.getuid() })
		if #result > 0 then
			result = (GetHostOs() == "WINDOWS" and "/C/Users/%s" or "/home/%s") % result
		end
		log(result.failure and kLogError or kLogDebug, result.failure or result)
		result = not result.failure and result or nil
	end
	return result
end

function system.network_adapter(address)
	local with_address = type(address) == "table" and address.with or address
	local without_address = type(address) == "table" and address.without or nil
	local identity = function(arg)
		return arg
	end
	local with_format = type(with_address) == "number" and identity or FormatIp
	local without_format = type(without_address) == "number" and identity or FormatIp
	for _, adapter in ipairs(unix.siocgifconf()) do
		-- log(kLogInfo, "%s == %s" % { with_address, with_format(adapter.ip) or "nil" })
		if with_address == with_format(adapter.ip) then
			return adapter
		elseif without_address and adapter.name ~= "lo" and without_address ~= without_format(adapter.ip) then
			return adapter
		end
	end
	with_address = type(with_address) == "number" and FormatIp(with_address) or with_address or "nil"
	without_address = type(without_address) == "number" and FormatIp(without_address) or without_address or "nil"
	return { name = "network_adapter(with_address=%s, without_address=%s) not found" % { with_address, without_address }, ip = nil, netmask = 32 }
end

function system.pid_dir()
	return GetHostOs() ~= "WINDOWS" and "/run" or system.env("APPDATA", "/C/Windows")
end

function system.system(cmd)
	log(kLogInfo, "executing %s: %s" % { cmd, inspect(table.pack(os.execute(cmd)), { newline = "", indent = "  " }) })
end

-- documented .com / .exe suffixing did not work
function system.which(name, ignore_not_found)
	local path, error = unix.commandv(GetHostOs() == "WINDOWS" and ("%s.exe" % { name }) or name)
	if error then
		log(ignore_not_found and kLogWarn or kLogFatal, "%s '%s'" % { error, name })
		return nil
	elseif GetHostOs() == "WINDOWS" and path:find(" ") then
		path = "\"%s\"" % { path }
	end
	log(kLogInfo, "%s found at: '%s'" % { name, path })
	return path
end

setmetatable(system, {
	__call = function(_, cmd)
		return system.system(cmd)
	end,
})

return system
