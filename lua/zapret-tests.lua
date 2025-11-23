-- nfqws2 C functions tests
-- to run : --lua-init=@zapret-lib.lua --lua-init=@zapret-tests.lua --lua-init="test_all()"

function test_assert(b)
	assert(b, "test failed")
end

function test_run(tests)
	for k,f in pairs(tests) do
		f()
	end
end


function test_all()
	test_run({test_crypto, test_bin, test_ipstr, test_dissect, test_csum, test_resolve, test_rawsend})
end


function test_crypto()
	test_run({test_random, test_aes, test_aes_gcm, test_aes_ctr, test_hkdf, test_hash})
end

function test_random()
	local rnds={}
	for i=1,20 do
		local rnd = bcryptorandom(math.random(10,20))
		print("random: "..string2hex(rnd))
		test_assert(not rnds[rnd]) -- should not be repeats
		rnds[rnd] = true
	end
end

function test_hash()
	local hashes={}
	for i=1,5 do
		local rnd = brandom(math.random(5,64))
		print("data:   "..string2hex(rnd))
		for k,sha in pairs({"sha256","sha224"}) do
			local hsh = hash(sha, rnd)
			print(sha..": "..string2hex(hsh))
			local hsh2 = hash(sha, rnd)
			test_assert(hsh==hsh2)
			test_assert(not hashes[hsh])
			hashes[hsh] = true
		end
	end
end

function test_hkdf()
	local nblob = 2
	local okms = {}
	for nsalt=1,nblob do
		local salt = brandom(math.random(10,20))
		for nikm=1,nblob do
			local ikm = brandom(math.random(5,10))
			for ninfo=1,nblob do
				local info = brandom(math.random(5,10))
				local okm_prev
				for k,sha in pairs({"sha256","sha224"}) do
					for k,okml in pairs({8, 16, 50}) do
					local okm_prev
						local okm
						print("* hkdf "..sha)
						print("salt: "..string2hex(salt))
						print("ikm : "..string2hex(ikm))
						print("info: "..string2hex(info))
						print("okml: "..tostring(okml))
						okm = hkdf(sha, salt, ikm, info, okml)
						test_assert(okm)
						print("okm: "..string2hex(okm))
						if okms[okm] then
							print("duplicate okm !")
						end
						okms[okm] = true

						test_assert(not okm_prev or okm_prev==string.sub(okm, 1, #okm_prev))
						okm_prev = okm
					end
				end
			end
		end
	end
end

function test_aes()
	local clear_text="test "..brandom_az09(11)
	local iv, key, encrypted, decrypted

	for key_size=16,32,8 do
		local key = brandom(key_size)

		print()
		print("* aes test key_size "..tostring(key_size))

		print("clear text: "..clear_text);

		print("* encrypting")
		encrypted = aes(true, key, clear_text)
		print("encrypted: "..str_or_hex(encrypted))

		print("* decrypting everything good")
		decrypted = aes(false, key, encrypted)
		print("decrypted: "..str_or_hex(decrypted))
		print( decrypted==clear_text and "DECRYPT OK" or "DECRYPT ERROR" )
		test_assert(decrypted==clear_text)

		print("* decrypting bad payload with good key")
		decrypted = aes(false, key, brandom(16))
		print("decrypted: "..str_or_hex(decrypted))
		print( decrypted==clear_text and "DECRYPT OK" or "DECRYPT ERROR" )
		test_assert(decrypted~=clear_text)

		print("* decrypting good payload with bad key")
		decrypted = aes(false, brandom(key_size), encrypted)
		print("decrypted: "..str_or_hex(decrypted))
		print( decrypted==clear_text and "DECRYPT OK" or "DECRYPT ERROR" )
		test_assert(decrypted~=clear_text)

	end
end

function test_aes_gcm()
	local authenticated_data = "authenticated message "..brandom_az09(math.random(10,50))
	local clear_text="test message "..brandom_az09(math.random(10,50))
	local iv, key, encrypted, atag, decrypted, atag2

	for key_size=16,32,8 do
		iv = brandom(12)
		key = brandom(key_size)

		print()
		print("* aes_gcm test key_size "..tostring(key_size))

		print("clear text: "..clear_text);
		print("authenticated data: "..authenticated_data);

		print("* encrypting")
		encrypted, atag = aes_gcm(true, key, iv, clear_text, authenticated_data)
		print("encrypted: "..str_or_hex(encrypted))
		print("auth tag: "..string2hex(atag))

		print("* decrypting everything good")
		decrypted, atag2 = aes_gcm(false, key, iv, encrypted, authenticated_data)
		print("decrypted: "..str_or_hex(decrypted))
		print( decrypted==clear_text and "DECRYPT OK" or "DECRYPT ERROR" )
		test_assert(decrypted==clear_text)
		print("auth tag: "..string2hex(atag2))
		print( atag==atag2 and "TAG OK" or "TAG ERROR" )
		test_assert(atag==atag2)

		print("* decrypting bad payload with good key/iv and correct authentication data")
		decrypted, atag2 = aes_gcm(false, key, iv, brandom(#encrypted), authenticated_data)
		print("decrypted: "..str_or_hex(decrypted))
		print( decrypted==clear_text and "DECRYPT OK" or "DECRYPT ERROR" )
		test_assert(decrypted~=clear_text)
		print("auth tag: "..string2hex(atag2))
		print( atag==atag2 and "TAG OK" or "TAG ERROR" )
		test_assert(atag~=atag2)

		print("* decrypting good payload with good key/iv and incorrect authentication data")
		decrypted, atag2 = aes_gcm(false, key, iv, encrypted, authenticated_data.."x")
		print("decrypted: "..str_or_hex(decrypted))
		print( decrypted==clear_text and "DECRYPT OK" or "DECRYPT ERROR" )
		test_assert(decrypted==clear_text)
		print("auth tag: "..string2hex(atag2))
		print( atag==atag2 and "TAG OK" or "TAG ERROR" )
		test_assert(atag~=atag2)

		print("* decrypting good payload with bad key, good iv and correct authentication data")
		decrypted, atag2 = aes_gcm(false, brandom(key_size), iv, encrypted, authenticated_data)
		print("decrypted: "..str_or_hex(decrypted))
		print( decrypted==clear_text and "DECRYPT OK" or "DECRYPT ERROR" )
		test_assert(decrypted~=clear_text)
		print("auth tag: "..string2hex(atag2))
		print( atag==atag2 and "TAG OK" or "TAG ERROR" )
		test_assert(atag~=atag2)

		print("* decrypting good payload with good key, bad iv and correct authentication data")
		decrypted, atag2 = aes_gcm(false, key, brandom(12), encrypted, authenticated_data)
		print("decrypted: "..str_or_hex(decrypted))
		print( decrypted==clear_text and "DECRYPT OK" or "DECRYPT ERROR" )
		test_assert(decrypted~=clear_text)
		print("auth tag: "..string2hex(atag2))
		print( atag==atag2 and "TAG OK" or "TAG ERROR" )
		test_assert(atag~=atag2)
	end
end

function test_aes_ctr()
	local clear_text="test message "..brandom_az09(math.random(10,50))
	local iv, key, encrypted, decrypted

	for key_size=16,32,8 do
		iv = brandom(16)
		key = brandom(key_size)

		print()
		print("* aes_ctr test key_size "..tostring(key_size))

		print("clear text: "..clear_text);

		print("* encrypting")
		encrypted = aes_ctr(key, iv, clear_text)
		print("encrypted: "..str_or_hex(encrypted))

		print("* decrypting")
		decrypted = aes_ctr(key, iv, encrypted)
		print("decrypted: "..str_or_hex(decrypted))
		print( decrypted==clear_text and "DECRYPT OK" or "DECRYPT ERROR" )
		test_assert(decrypted==clear_text)

		print("* decrypting with bad key")
		decrypted = aes_ctr(bu8(u8(string.sub(key,1,1))+1)..string.sub(key,2), iv, encrypted)
		print("decrypted: "..str_or_hex(decrypted))
		print( decrypted==clear_text and "DECRYPT OK" or "DECRYPT ERROR" )
		test_assert(decrypted~=clear_text)

		print("* decrypting with bad iv")
		decrypted = aes_ctr(key, bu8(u8(string.sub(iv,1,1))+1)..string.sub(iv,2), encrypted)
		print("decrypted: "..str_or_hex(decrypted))
		print( decrypted==clear_text and "DECRYPT OK" or "DECRYPT ERROR" )
		test_assert(decrypted~=clear_text)
	end
end


function test_ub()
	for k,f in pairs({{u8,bu8,0xFF,8}, {u16,bu16,0xFFFF,16}, {u24,bu24,0xFFFFFF,24}, {u32,bu32,0xFFFFFFFF,32}}) do
		local v = math.random(0,f[3])
		local pos = math.random(1,20)
		local s = brandom(pos-1)..f[2](v)..brandom(20)
		local v2 = f[1](s,pos)
		print("u"..tostring(f[4]).." pos="..tostring(pos).." "..tostring(v).." "..tostring(v2))
		test_assert(v==v2)
	end
end

function test_bit()
	local v, v2, v3, v4, b1, b2, pow

	v = math.random(0,0xFFFFFFFFFFFF)
	b1 = math.random(1,15)

	v2 = bitrshift(v, b1)
	pow = 2^b1
	v3 = divint(v, pow)
	print(string.format("rshift(0x%X,%u) = 0x%X  0x%X/%u = 0x%X", v,b1,v2, v,pow,v3))
	test_assert(v2==v3)

	v2 = bitlshift(v, b1)
	pow = 2^b1
	v3 = v * pow
	print(string.format("lshift(0x%X,%u) = 0x%X  0x%X*%u = 0x%X", v,b1,v2, v,pow,v3))
	test_assert(v2==v3)

	v2 = math.random(0,0xFFFFFFFFFFFF)
	v3 = bitxor(v, v2)
	v4 = bitor(v, v2) - bitand(v, v2)
	print(string.format("xor(0x%X,0x%X) = %X  or/and/minus = %X", v, v2, v3, v4))
	test_assert(v3==v4)

	b2 = b1 + math.random(1,31)
	v2 = bitget(v, b1, b2)
	pow = 2^(b2-b1+1) - 1
	v3 = bitand(bitrshift(v,b1), pow)
	print(string.format("bitget(0x%X,%u,%u) = 0x%X  bitand/bitrshift/pow = 0x%X", v, b1, b2, v2, v3))
	test_assert(v2==v3)

	v4 = math.random(0,pow)
	v2 = bitset(v, b1, b2, v4)
	v3 = bitor(bitlshift(v4, b1), bitand(v, bitnot(bitlshift(pow, b1))))
	print(string.format("bitset(0x%X,%u,%u,0x%X) = 0x%X  bitand/bitnot/bitlshift/pow = 0x%X", v, b1, b2, v4, v2, v3))
	test_assert(v2==v3)
end

function test_bin()
	test_run({test_ub, test_bit})
end


function test_ipstr()
	local s_ip, ip, s_ip2

	s_ip = string.format("%u.%u.%u.%u", math.random(0,255), math.random(0,255), math.random(0,255), math.random(0,255));
	ip = pton(s_ip)
	s_ip2 = ntop(ip)
	print("IP: "..s_ip)
	print("IPBIN: "..string2hex(ip))
	print("IP2: "..s_ip2)
	test_assert(s_ip==s_ip2)

	s_ip = string.format("%x:%x:%x:%x:%x:%x:%x:%x", math.random(1,0xFFFF), math.random(1,0xFFFF), math.random(1,0xFFFF), math.random(1,0xFFFF), math.random(1,0xFFFF), math.random(1,0xFFFF), math.random(1,0xFFFF), math.random(1,0xFFFF));
	ip = pton(s_ip)
	s_ip2 = ntop(ip)
	print("IP: "..s_ip)
	print("IPBIN: "..string2hex(ip))
	print("IP2: "..s_ip2)
	test_assert(s_ip==s_ip2)
end


function test_dissect()
	local dis, raw1, raw2

	for i=1,20 do
		print("* dissect test "..tostring(i))

		local ip_tcp = {
			ip = {
				ip_tos = math.random(0,255),
				ip_id = math.random(0,0xFFFF),
				ip_off = 0,
				ip_ttl = math.random(0,255),
				ip_p = IPPROTO_TCP,
				ip_src = brandom(4),
				ip_dst = brandom(4),
				options = brandom(math.random(0,40))
			},
			tcp = {
				th_sport = math.random(0,0xFFFF),
				th_dport = math.random(0,0xFFFF),
				th_seq = math.random(0,0xFFFFFFFF),
				th_ack = math.random(0,0xFFFFFFFF),
				th_x2 = math.random(0,0xF),
				th_flags = math.random(0,0xFF),
				th_win = math.random(0,0xFFFF),
				th_urp = math.random(0,0xFFFF),
				options = {
					{ kind = 1 },
					{ kind = 0xE0, data = brandom(math.random(1,10)) },
					{ kind = 1 },
					{ kind = 0xE1, data = brandom(math.random(1,10)) },
					{ kind = 0 }
				}
			},
			payload = brandom(math.random(0, 20))
		}
		raw1 = reconstruct_dissect(ip_tcp)
		print("IP+TCP : "..string2hex(raw1))
		dis1 = dissect(raw1);
		raw2 = reconstruct_dissect(dis1)
		dis2 = dissect(raw2);
		print("IP+TCP2: "..string2hex(raw2))
		print( raw1==raw2 and "DISSECT OK" or "DISSECT FAILED" )
		test_assert(raw1==raw2)

		local ip6_udp = {
			ip6 = {
				ip6_flow = 0x60000000 + math.random(0,0xFFFFFFF),
				ip6_hlim = math.random(1,0xFF),
				ip6_src = brandom(16),
				ip6_dst = brandom(16),
				exthdr = {
					{ type = IPPROTO_HOPOPTS, data = brandom(6+8*math.random(0,2)) },
					{ type = IPPROTO_AH, data = brandom(6+4*math.random(0,4)) }
				}
			},
			udp = {
				uh_sport = math.random(0,0xFFFF),
				uh_dport = math.random(0,0xFFFF)
			},
			payload = brandom(math.random(0, 20))
		}
	
		raw1 = reconstruct_dissect(ip6_udp)
		print("IP6+UDP : "..string2hex(raw1))
		dis1 = dissect(raw1);
		raw2 = reconstruct_dissect(dis1)
		dis2 = dissect(raw2);
		print("IP6+UDP2: "..string2hex(raw2))
		print( raw1==raw2 and "DISSECT OK" or "DISSECT FAILED" )
		test_assert(raw1==raw2)
	end
end

function test_csum()
	local payload = brandom(math.random(10,20))
	local ip4b, ip6b, raw, tcpb, udpb, dis1, dis2
	local ip = {
		ip_tos = math.random(0,255),
		ip_id = math.random(0,0xFFFF),
		ip_len = math.random(0,0xFFFF),
		ip_off = 0,
		ip_ttl = math.random(0,255),
		ip_p = IPPROTO_TCP,
		ip_src = brandom(4),
		ip_dst = brandom(4),
		options = brandom(4*math.random(0,10))
	}
	ip4b = reconstruct_iphdr(ip)
	raw =	bu8(0x40 + 5 + #ip.options/4) ..
		bu8(ip.ip_tos) ..
		bu16(ip.ip_len) ..
		bu16(ip.ip_id) ..
		bu16(ip.ip_off) ..
		bu8(ip.ip_ttl) ..
		bu8(ip.ip_p) ..
		bu16(0) ..
		ip.ip_src .. ip.ip_dst ..
		ip.options
	raw = csum_ip4_fix(raw)
	print( raw==ip4b and "IP4 RECONSTRUCT+CSUM OK" or "IP4 RECONSTRUCT+CSUM FAILED" )
	test_assert(raw==ip4b)


	local tcp = {
		th_sport = math.random(0,0xFFFF),
		th_dport = math.random(0,0xFFFF),
		th_seq = math.random(0,0xFFFFFFFF),
		th_ack = math.random(0,0xFFFFFFFF),
		th_x2 = math.random(0,0xF),
		th_flags = math.random(0,0xFF),
		th_win = math.random(0,0xFFFF),
		th_urp = math.random(0,0xFFFF),
		options = {
			{ kind = 1 },
			{ kind = 0xE0, data = brandom(math.random(1,10)) },
			{ kind = 1 },
			{ kind = 0xE1, data = brandom(math.random(1,10)) },
			{ kind = 0 }
		}
	}
	tcpb = reconstruct_tcphdr(tcp)
	raw =	bu16(tcp.th_sport) ..
		bu16(tcp.th_dport) ..
		bu32(tcp.th_seq) ..
		bu32(tcp.th_ack) ..
		bu8(l4_len({tcp = tcp}) * 4 + tcp.th_x2) ..
		bu8(tcp.th_flags) ..
		bu16(tcp.th_win) ..
		bu16(0) ..
		bu16(tcp.th_urp) ..
		bu8(tcp.options[1].kind)..
		bu8(tcp.options[2].kind)..bu8(2 + #tcp.options[2].data)..tcp.options[2].data ..
		bu8(tcp.options[3].kind)..
		bu8(tcp.options[4].kind)..bu8(2 + #tcp.options[4].data)..tcp.options[4].data ..
		bu8(tcp.options[5].kind)
	raw = raw .. string.rep(bu8(TCP_KIND_NOOP), bitand(4-bitand(#raw,3),3))
	print( raw==tcpb and "TCP RECONSTRUCT OK" or "TCP RECONSTRUCT FAILED" )
	test_assert(raw==tcpb)

	raw = reconstruct_dissect({ip=ip, tcp=tcp, payload=payload})
	dis1 = dissect(raw)
	tcpb = csum_tcp_fix(ip4b,tcpb,payload)
	dis2 = dissect(ip4b..tcpb..payload)
	print( dis1.tcp.th_sum==dis2.tcp.th_sum and "TCP+IP4 CSUM OK" or "TCP+IP4 CSUM FAILED" )
	test_assert(dis1.tcp.th_sum==dis2.tcp.th_sum)


	local ip6 = {
		ip6_flow = 0x60000000 + math.random(0,0xFFFFFFF),
		ip6_hlim = math.random(1,0xFF),
		ip6_src = brandom(16),
		ip6_dst = brandom(16),
		exthdr = {
			{ type = IPPROTO_HOPOPTS, data = brandom(6+8*math.random(0,2)) }
		}
	}
	ip6.ip6_plen = packet_len({ip6=ip6,tcp=tcp,payload=payload}) - IP6_BASE_LEN
	ip6b = reconstruct_ip6hdr(ip6, {ip6_last_proto=IPPROTO_TCP})
	raw =	bu32(ip6.ip6_flow) ..
		bu16(ip6.ip6_plen) ..
		bu8(ip6.exthdr[1].type) ..
		bu8(ip6.ip6_hlim) ..
		ip6.ip6_src .. ip6.ip6_dst ..
		bu8(IPPROTO_TCP) ..
		bu8((#ip6.exthdr[1].data+2)/8 - 1) ..
		ip6.exthdr[1].data
	print( raw==ip6b and "IP6 RECONSTRUCT OK" or "IP6 RECONSTRUCT FAILED" )
	test_assert(raw==ip6b)

	raw = reconstruct_dissect({ip6=ip6, tcp=tcp, payload=payload})
	dis1 = dissect(raw)
	tcpb = csum_tcp_fix(ip6b,tcpb,payload)
	dis2 = dissect(ip6b..tcpb..payload)
	print( dis1.tcp.th_sum==dis2.tcp.th_sum and "TCP+IP6 CSUM OK" or "TCP+IP6 CSUM FAILED" )
	test_assert(dis1.tcp.th_sum==dis2.tcp.th_sum)


	ip.ip_p = IPPROTO_UDP
	ip4b = reconstruct_iphdr(ip)
	ip6.ip6_plen = packet_len({ip6=ip6,udp=udp,payload=payload}) - IP6_BASE_LEN
	ip6b = reconstruct_ip6hdr(ip6, {ip6_last_proto=IPPROTO_UDP})

	local udp = {
		uh_sport = math.random(0,0xFFFF),
		uh_dport = math.random(0,0xFFFF),
		uh_ulen = UDP_BASE_LEN + #payload
	}

	udpb = reconstruct_udphdr(udp)
	raw =	bu16(udp.uh_sport) ..
		bu16(udp.uh_dport) ..
		bu16(udp.uh_ulen) ..
		bu16(0)
	print( raw==udpb and "UDP RECONSTRUCT OK" or "UDP RECONSTRUCT FAILED" )
	test_assert(raw==udpb)

	raw = reconstruct_dissect({ip=ip, udp=udp, payload=payload})
	dis1 = dissect(raw)
	udpb = csum_udp_fix(ip4b,udpb,payload)
	dis2 = dissect(ip4b..udpb..payload)
	print( dis1.udp.uh_sum==dis2.udp.uh_sum and "UDP+IP4 CSUM OK" or "UDP+IP4 CSUM FAILED" )
	test_assert(dis1.udp.uh_sum==dis2.udp.uh_sum)

	raw = reconstruct_dissect({ip6=ip6, udp=udp, payload=payload})
	dis1 = dissect(raw)
	udpb = csum_udp_fix(ip6b,udpb,payload)
	dis2 = dissect(ip6b..udpb..payload)
	print( dis1.udp.uh_sum==dis2.udp.uh_sum and "UDP+IP6 CSUM OK" or "UDP+IP6 CSUM FAILED" )
	test_assert(dis1.udp.uh_sum==dis2.udp.uh_sum)
end

function test_resolve()
	local pos

	pos = zero_based_pos(resolve_multi_pos(fake_default_tls,"tls_client_hello","1,extlen,sniext,host,sld,midsld,endsld,endhost,-5"))
	test_assert(pos)
	print("resolve_multi_pos tls : "..table.concat(pos," "))
	pos = zero_based_pos(resolve_range(fake_default_tls,"tls_client_hello","host,endhost"))
	test_assert(pos)
	print("resolve_range tls : "..table.concat(pos," "))
	pos = resolve_pos(fake_default_tls,"tls_client_hello","midsld")
	test_assert(pos)
	print("resolve_pos tls : "..pos - 1)
	pos = resolve_pos(fake_default_tls,"tls_client_hello","method")
	test_assert(not pos)
	print("resolve_pos tls non-existent : "..tostring(pos))

	pos = zero_based_pos(resolve_multi_pos(fake_default_http,"http_req","method,host,sld,midsld,endsld,endhost,-5"))
	test_assert(pos)
	print("resolve_multi_pos http : "..table.concat(pos," "))
	pos = resolve_pos(fake_default_http,"http_req","sniext")
	test_assert(not pos)
	print("resolve_pos http non-existent : "..tostring(pos))
end

function test_rawsend()
	local ip, ip6, udp, dis, ddis, raw_ip, raw_udp, raw
	local payload = brandom(math.random(100,1200))

	ip = {
		ip_tos = 0,
		ip_id = math.random(0,0xFFFF),
		ip_off = 0,
		ip_ttl = 1,
		ip_p = IPPROTO_UDP,
		ip_src = pton("192.168.1.1"),
		ip_dst = pton("192.168.1.2")
	}
	udp = {
		uh_sport = math.random(0,0xFFFF),
		uh_dport = math.random(0,0xFFFF)
	}
	dis = {ip = ip, udp = udp, payload = payload}
	print("send ipv4 udp")
	test_assert(rawsend_dissect(dis, {repeats=3}))

	ddis = ipfrag2(dis, {ipfrag_pos_udp = 80})
	for k,d in pairs(ddis) do
		print("send ipv4 udp frag "..k)
		test_assert(rawsend_dissect(d))
	end

	raw_ip = reconstruct_iphdr(ip)
	raw_udp = reconstruct_udphdr({uh_sport = udp.uh_sport, uh_dport = udp.uh_dport, uh_ulen = UDP_BASE_LEN + #payload})
	raw_udp = csum_udp_fix(raw_ip,raw_udp,payload)
	raw = raw_ip .. raw_udp .. payload
	print("send ipv4 udp using pure rawsend without dissect")
	test_assert(rawsend(raw, {repeats=5}))

	ip6 = {
		ip6_flow = 0x60000000,
		ip6_hlim = 1,
		ip6_src = pton("fdce:3124:164a:5318::1"),
		ip6_dst = pton("fdce:3124:164a:5318::2")
	}
	dis = {ip6 = ip6, udp = udp, payload = payload}
	print("send ipv6 udp")
	test_assert(rawsend_dissect(dis, {repeats=3}))

	ddis = ipfrag2(dis, {ipfrag_pos_udp = 80})
	for k,d in pairs(ddis) do
		print("send ipv6 udp frag "..k)
		test_assert(rawsend_dissect(d))
	end

	ip6.exthdr={{ type = IPPROTO_HOPOPTS, data = "\x00\x00\x00\x00\x00\x00" }}
	print("send ipv6 udp with hopbyhop ext header")
	test_assert(rawsend_dissect(dis, {repeats=3}))

	ddis = ipfrag2(dis, {ipfrag_pos_udp = 80})
	for k,d in pairs(ddis) do
		print("send ipv6 udp frag "..k.." with hopbyhop ext header")
		test_assert(rawsend_dissect(d))
	end

	table.insert(ip6.exthdr, { type = IPPROTO_DSTOPTS, data = "\x00\x00\x00\x00\x00\x00" })
	table.insert(ip6.exthdr, { type = IPPROTO_DSTOPTS, data = "\x00\x00\x00\x00\x00\x00" })
	ip6.ip6_flow = 0x60001234;
	ddis = ipfrag2(dis, {ipfrag_pos_udp = 80})
	for k,d in pairs(ddis) do
		print("send ipv6 udp frag "..k.." with hopbyhop, destopt ext headers in unfragmentable part and another destopt ext header in fragmentable part")
		test_assert(rawsend_dissect(d, {fwmark = 0x50EA}))
	end

	fix_ip6_next(ip6) -- required to forge next proto in the second fragment
	ip6.ip6_flow = 0x6000AE38;
	ddis = ipfrag2(dis, {ipfrag_pos_udp = 80, ipfrag_next = IPPROTO_TCP})
	for k,d in pairs(ddis) do
		print("send ipv6 udp frag "..k.." with hopbyhop, destopt ext headers in unfragmentable part and another destopt ext header in fragmentable part. forge next proto in fragment header of the second fragment to TCP")
		-- reconstruct dissect using next proto fields in the dissect. do not auto fix next proto chain.
		-- by default reconstruct fixes next proto chain
		test_assert(rawsend_dissect(d, {fwmark = 0x409A, repeats=2}, {ip6_preserve_next = true}))
	end
end
