-- test case : nfqws2 --qnum 200 --debug --lua-init=@zapret-lib.lua --lua-init=@zapret-pcap.lua:file=test.pcap --writeable=zdir
-- arg : file=<filename> - file for storing pcap data. if --writeable is specified and filename is relative - append filename to writeable path
function pcap(ctx, desync)
	if not desync.arg.file or #desync.arg.file==0 then
		error("pcap requires 'file' parameter")
	end
	local fn = writeable_file_name(desync.arg.file)
	local f = io.open(fn, "a")
	if not f then
		error("pcap: could not write to '"..fn.."'")
	end
	local pos = f:seek()
	if (pos==0) then
		-- create pcap header
		f:write("\xA1\xB2\x3C\x4D\x00\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x65")
	end
	local raw = raw_packet(ctx)
	local sec, nsec = clock_gettime();
	f:write(bu32(sec)..bu32(nsec)..bu32(#raw)..bu32(#raw))
	f:write(raw)
	f:close()
end
