#include "conntrack.h"
#include "darkmagic.h"
#include <arpa/inet.h>
#include <stdio.h>

#include "params.h"
#include "lua.h"

#undef uthash_nonfatal_oom
#define uthash_nonfatal_oom(elt) ut_oom_recover(elt)

static bool oom = false;
static void ut_oom_recover(void *elem)
{
	oom = true;
}

static const char *connstate_s[] = { "SYN","ESTABLISHED","FIN" };

static void connswap(const t_conn *c, t_conn *c2)
{
	memset(c2, 0, sizeof(*c2));
	c2->l3proto = c->l3proto;
	c2->l4proto = c->l4proto;
	c2->src = c->dst;
	c2->dst = c->src;
	c2->sport = c->dport;
	c2->dport = c->sport;
}

void ConntrackClearHostname(t_ctrack *track)
{
	free(track->hostname);
	track->hostname = NULL;
	track->hostname_is_ip = false;
}
static void ConntrackClearTrack(t_ctrack *track)
{
	ConntrackClearHostname(track);
	ReasmClear(&track->reasm_orig);
	rawpacket_queue_destroy(&track->delayed);
	luaL_unref(params.L, LUA_REGISTRYINDEX, track->lua_state);
	luaL_unref(params.L, LUA_REGISTRYINDEX, track->lua_instance_cutoff);
}

static void ConntrackFreeElem(t_conntrack_pool *elem)
{
	ConntrackClearTrack(&elem->track);
	free(elem);
}

static void ConntrackPoolDestroyPool(t_conntrack_pool **pp)
{
	t_conntrack_pool *elem, *tmp;
	HASH_ITER(hh, *pp, elem, tmp) { HASH_DEL(*pp, elem); ConntrackFreeElem(elem); }
}
void ConntrackPoolDestroy(t_conntrack *p)
{
	ConntrackPoolDestroyPool(&p->pool);
}

void ConntrackPoolInit(t_conntrack *p, time_t purge_interval, uint32_t timeout_syn, uint32_t timeout_established, uint32_t timeout_fin, uint32_t timeout_udp)
{
	p->timeout_syn = timeout_syn;
	p->timeout_established = timeout_established;
	p->timeout_fin = timeout_fin;
	p->timeout_udp = timeout_udp;
	p->t_purge_interval = purge_interval;
	time(&p->t_last_purge);
	p->pool = NULL;
}

void ConntrackExtractConn(t_conn *c, bool bReverse, const struct ip *ip, const struct ip6_hdr *ip6, const struct tcphdr *tcphdr, const struct udphdr *udphdr)
{
	memset(c, 0, sizeof(*c));
	if (ip)
	{
		c->l3proto = IPPROTO_IP;
		c->dst.ip = bReverse ? ip->ip_src : ip->ip_dst;
		c->src.ip = bReverse ? ip->ip_dst : ip->ip_src;
	}
	else if (ip6)
	{
		c->l3proto = IPPROTO_IPV6;
		c->dst.ip6 = bReverse ? ip6->ip6_src : ip6->ip6_dst;
		c->src.ip6 = bReverse ? ip6->ip6_dst : ip6->ip6_src;
	}
	else
		c->l3proto = -1;
	extract_ports(tcphdr, udphdr, &c->l4proto, bReverse ? &c->dport : &c->sport, bReverse ? &c->sport : &c->dport);
}


static t_conntrack_pool *ConntrackPoolSearch(t_conntrack_pool *p, const t_conn *c)
{
	t_conntrack_pool *t;
	HASH_FIND(hh, p, c, sizeof(*c), t);
	return t;
}

static void ConntrackInitTrack(t_ctrack *t)
{
	memset(t, 0, sizeof(*t));
	t->l7proto = L7_UNKNOWN;
	t->pos.scale_orig = t->pos.scale_reply = SCALE_NONE;
	time(&t->pos.t_start);
	rawpacket_queue_init(&t->delayed);
	lua_newtable(params.L);
	t->lua_state = luaL_ref(params.L, LUA_REGISTRYINDEX);
	lua_newtable(params.L);
	t->lua_instance_cutoff = luaL_ref(params.L, LUA_REGISTRYINDEX);
}
static void ConntrackReInitTrack(t_ctrack *t)
{
	ConntrackClearTrack(t);
	ConntrackInitTrack(t);
}

static t_conntrack_pool *ConntrackNew(t_conntrack_pool **pp, const t_conn *c)
{
	t_conntrack_pool *ctnew;
	if (!(ctnew = malloc(sizeof(*ctnew)))) return NULL;
	ctnew->conn = *c;
	oom = false;
	HASH_ADD(hh, *pp, conn, sizeof(*c), ctnew);
	if (oom) { free(ctnew); return NULL; }
	ConntrackInitTrack(&ctnew->track);
	return ctnew;
}

// non-tcp packets are passed with tcphdr=NULL but len_payload filled
static void ConntrackFeedPacket(t_ctrack *t, bool bReverse, const struct tcphdr *tcphdr, uint32_t len_payload)
{
	uint8_t scale;
	uint16_t mss;

	if (bReverse)
	{
		t->pos.pcounter_reply++;
		t->pos.pdcounter_reply += !!len_payload;
		t->pos.pbcounter_reply += len_payload;
	}

	else
	{
		t->pos.pcounter_orig++;
		t->pos.pdcounter_orig += !!len_payload;
		t->pos.pbcounter_orig += len_payload;
	}

	if (tcphdr)
	{
		if (tcp_syn_segment(tcphdr))
		{
			if (t->pos.state != SYN) ConntrackReInitTrack(t); // erase current entry
			t->pos.seq0 = ntohl(tcphdr->th_seq);
		}
		else if (tcp_synack_segment(tcphdr))
		{
			// ignore SA dups
			uint32_t seq0 = ntohl(tcphdr->th_ack) - 1;
			if (t->pos.state != SYN && t->pos.seq0 != seq0)
				ConntrackReInitTrack(t); // erase current entry
			if (!t->pos.seq0) t->pos.seq0 = seq0;
			t->pos.ack0 = ntohl(tcphdr->th_seq);
		}
		else if (tcphdr->th_flags & (TH_FIN | TH_RST))
		{
			t->pos.state = FIN;
		}
		else
		{
			if (t->pos.state == SYN)
			{
				t->pos.state = ESTABLISHED;
				if (!bReverse && !t->pos.ack0) t->pos.ack0 = ntohl(tcphdr->th_ack) - 1;
			}
		}
		scale = tcp_find_scale_factor(tcphdr);
		mss = ntohs(tcp_find_mss(tcphdr));
		if (bReverse)
		{
			t->pos.pos_orig = t->pos.seq_last = ntohl(tcphdr->th_ack);
			t->pos.ack_last = ntohl(tcphdr->th_seq);
			t->pos.pos_reply = t->pos.ack_last + len_payload;
			t->pos.winsize_reply = ntohs(tcphdr->th_win);
			t->pos.winsize_reply_calc = t->pos.winsize_reply;
			if (t->pos.scale_reply != SCALE_NONE) t->pos.winsize_reply_calc <<= t->pos.scale_reply;
			if (mss && !t->pos.mss_reply) t->pos.mss_reply = mss;
			if (scale != SCALE_NONE) t->pos.scale_reply = scale;
		}
		else
		{
			t->pos.seq_last = ntohl(tcphdr->th_seq);
			t->pos.pos_orig = t->pos.seq_last + len_payload;
			t->pos.pos_reply = t->pos.ack_last = ntohl(tcphdr->th_ack);
			t->pos.winsize_orig = ntohs(tcphdr->th_win);
			t->pos.winsize_orig_calc = t->pos.winsize_orig;
			if (t->pos.scale_orig != SCALE_NONE) t->pos.winsize_orig_calc <<= t->pos.scale_orig;
			if (mss && !t->pos.mss_reply) t->pos.mss_orig = mss;
			if (scale != SCALE_NONE) t->pos.scale_orig = scale;
		}
	}
	else
	{
		if (bReverse)
		{
			t->pos.ack_last = t->pos.pos_reply;
			t->pos.pos_reply += len_payload;
		}
		else
		{
			t->pos.seq_last = t->pos.pos_orig;
			t->pos.pos_orig += len_payload;
		}
	}

	time(&t->pos.t_last);
}

static bool ConntrackPoolDoubleSearchPool(t_conntrack_pool **pp, const struct ip *ip, const struct ip6_hdr *ip6, const struct tcphdr *tcphdr, const struct udphdr *udphdr, t_ctrack **ctrack, bool *bReverse)
{
	t_conn conn, connswp;
	t_conntrack_pool *ctr;

	ConntrackExtractConn(&conn, false, ip, ip6, tcphdr, udphdr);
	if ((ctr = ConntrackPoolSearch(*pp, &conn)))
	{
		if (bReverse) *bReverse = false;
		if (ctrack) *ctrack = &ctr->track;
		return true;
	}
	else
	{
		connswap(&conn, &connswp);
		if ((ctr = ConntrackPoolSearch(*pp, &connswp)))
		{
			if (bReverse) *bReverse = true;
			if (ctrack) *ctrack = &ctr->track;
			return true;
		}
	}
	return false;
}
bool ConntrackPoolDoubleSearch(t_conntrack *p, const struct ip *ip, const struct ip6_hdr *ip6, const struct tcphdr *tcphdr, const struct udphdr *udphdr, t_ctrack **ctrack, bool *bReverse)
{
	return ConntrackPoolDoubleSearchPool(&p->pool, ip, ip6, tcphdr, udphdr, ctrack, bReverse);
}

static bool ConntrackPoolFeedPool(t_conntrack_pool **pp, const struct ip *ip, const struct ip6_hdr *ip6, const struct tcphdr *tcphdr, const struct udphdr *udphdr, size_t len_payload, t_ctrack **ctrack, bool *bReverse)
{
	t_conn conn, connswp;
	t_conntrack_pool *ctr;
	bool b_rev;
	uint8_t proto = tcphdr ? IPPROTO_TCP : udphdr ? IPPROTO_UDP : IPPROTO_NONE;

	ConntrackExtractConn(&conn, false, ip, ip6, tcphdr, udphdr);
	if ((ctr = ConntrackPoolSearch(*pp, &conn)))
	{
		ConntrackFeedPacket(&ctr->track, (b_rev = false), tcphdr, len_payload);
		goto ok;
	}
	else
	{
		connswap(&conn, &connswp);
		if ((ctr = ConntrackPoolSearch(*pp, &connswp)))
		{
			ConntrackFeedPacket(&ctr->track, (b_rev = true), tcphdr, len_payload);
			goto ok;
		}
	}
	b_rev = tcphdr && tcp_synack_segment(tcphdr);
	if ((tcphdr && tcp_syn_segment(tcphdr)) || b_rev || udphdr)
	{
		if ((ctr = ConntrackNew(pp, b_rev ? &connswp : &conn)))
		{
			ConntrackFeedPacket(&ctr->track, b_rev, tcphdr, len_payload);
			goto ok;
		}
	}
	return false;
ok:
	ctr->track.ipproto = proto;
	if (ctrack) *ctrack = &ctr->track;
	if (bReverse) *bReverse = b_rev;
	return true;
}
bool ConntrackPoolFeed(t_conntrack *p, const struct ip *ip, const struct ip6_hdr *ip6, const struct tcphdr *tcphdr, const struct udphdr *udphdr, size_t len_payload, t_ctrack **ctrack, bool *bReverse)
{
	return ConntrackPoolFeedPool(&p->pool, ip, ip6, tcphdr, udphdr, len_payload, ctrack, bReverse);
}

static bool ConntrackPoolDropPool(t_conntrack_pool **pp, const struct ip *ip, const struct ip6_hdr *ip6, const struct tcphdr *tcphdr, const struct udphdr *udphdr)
{
	t_conn conn, connswp;
	t_conntrack_pool *t;
	ConntrackExtractConn(&conn, false, ip, ip6, tcphdr, udphdr);
	if (!(t = ConntrackPoolSearch(*pp, &conn)))
	{
		connswap(&conn, &connswp);
		t = ConntrackPoolSearch(*pp, &connswp);
	}
	if (!t) return false;
	HASH_DEL(*pp, t); ConntrackFreeElem(t);
	return true;
}
bool ConntrackPoolDrop(t_conntrack *p, const struct ip *ip, const struct ip6_hdr *ip6, const struct tcphdr *tcphdr, const struct udphdr *udphdr)
{
	return ConntrackPoolDropPool(&p->pool, ip, ip6, tcphdr, udphdr);
}

void ConntrackPoolPurge(t_conntrack *p)
{
	time_t tidle, tnow = time(NULL);
	t_conntrack_pool *t, *tmp;

	if ((tnow - p->t_last_purge) >= p->t_purge_interval)
	{
		HASH_ITER(hh, p->pool, t, tmp) {
			tidle = tnow - t->track.pos.t_last;
			if (t->track.b_cutoff ||
				(t->conn.l4proto == IPPROTO_TCP && (
				(t->track.pos.state == SYN && tidle >= p->timeout_syn) ||
					(t->track.pos.state == ESTABLISHED && tidle >= p->timeout_established) ||
					(t->track.pos.state == FIN && tidle >= p->timeout_fin))
					) || (t->conn.l4proto == IPPROTO_UDP && tidle >= p->timeout_udp)
				)
			{
				HASH_DEL(p->pool, t); ConntrackFreeElem(t);
			}
		}
		p->t_last_purge = tnow;
	}
}

static void taddr2str(uint8_t l3proto, const t_addr *a, char *buf, size_t bufsize)
{
	if (!inet_ntop(family_from_proto(l3proto), a, buf, bufsize) && bufsize) *buf = 0;
}

void ConntrackPoolDump(const t_conntrack *p)
{
	t_conntrack_pool *t, *tmp;
	char sa1[40], sa2[40];
	time_t tnow = time(NULL);
	HASH_ITER(hh, p->pool, t, tmp) {
		taddr2str(t->conn.l3proto, &t->conn.src, sa1, sizeof(sa1));
		taddr2str(t->conn.l3proto, &t->conn.dst, sa2, sizeof(sa2));
		printf("%s [%s]:%u => [%s]:%u : %s : t0=%llu last=t0+%llu now=last+%llu orig=d%llu/n%llu/b%llu reply=d%llu/n%llu/b%lld ",
			proto_name(t->conn.l4proto),
			sa1, t->conn.sport, sa2, t->conn.dport,
			t->conn.l4proto == IPPROTO_TCP ? connstate_s[t->track.pos.state] : "-",
			(unsigned long long)t->track.pos.t_start, (unsigned long long)(t->track.pos.t_last - t->track.pos.t_start), (unsigned long long)(tnow - t->track.pos.t_last),
			(unsigned long long)t->track.pos.pdcounter_orig, (unsigned long long)t->track.pos.pcounter_orig, (unsigned long long)t->track.pos.pbcounter_orig,
			(unsigned long long)t->track.pos.pdcounter_reply, (unsigned long long)t->track.pos.pcounter_reply, (unsigned long long)t->track.pos.pbcounter_reply);
		if (t->conn.l4proto == IPPROTO_TCP)
			printf("seq0=%u rseq=%u pos_orig=%u ack0=%u rack=%u pos_reply=%u mss_orig=%u mss_reply=%u wsize_orig=%u:%d wsize_reply=%u:%d",
				t->track.pos.seq0, t->track.pos.seq_last - t->track.pos.seq0, t->track.pos.pos_orig - t->track.pos.seq0,
				t->track.pos.ack0, t->track.pos.ack_last - t->track.pos.ack0, t->track.pos.pos_reply - t->track.pos.ack0,
				t->track.pos.mss_orig, t->track.pos.mss_reply,
				t->track.pos.winsize_orig, t->track.pos.scale_orig == SCALE_NONE ? -1 : t->track.pos.scale_orig,
				t->track.pos.winsize_reply, t->track.pos.scale_reply == SCALE_NONE ? -1 : t->track.pos.scale_reply);
		else
			printf("rseq=%u pos_orig=%u rack=%u pos_reply=%u",
				t->track.pos.seq_last, t->track.pos.pos_orig,
				t->track.pos.ack_last, t->track.pos.pos_reply);
		printf(" req_retrans=%u cutoff=%u lua_in_cutoff=%u lua_out_cutoff=%u hostname=%s l7proto=%s\n",
			t->track.req_retrans_counter, t->track.b_cutoff, t->track.b_lua_in_cutoff, t->track.b_lua_out_cutoff, t->track.hostname, l7proto_str(t->track.l7proto));
	};
}


void ReasmClear(t_reassemble *reasm)
{
	free(reasm->packet);
	reasm->packet = NULL;
	reasm->size = reasm->size_present = 0;
}
bool ReasmInit(t_reassemble *reasm, size_t size_requested, uint32_t seq_start)
{
	reasm->packet = malloc(size_requested);
	if (!reasm->packet) return false;
	reasm->size = size_requested;
	reasm->size_present = 0;
	reasm->seq = seq_start;
	return true;
}
bool ReasmResize(t_reassemble *reasm, size_t new_size)
{
	uint8_t *p = realloc(reasm->packet, new_size);
	if (!p) return false;
	reasm->packet = p;
	reasm->size = new_size;
	if (reasm->size_present > new_size) reasm->size_present = new_size;
	return true;
}
#define REASM_MAX_NEG 0x100000
bool ReasmFeed(t_reassemble *reasm, uint32_t seq, const void *payload, size_t len)
{
	uint32_t dseq = seq - reasm->seq;
	if (dseq && (dseq < REASM_MAX_NEG))
		return false; // fail session if a gap about to appear
	uint32_t neg_overlap = reasm->seq - seq;
	if (neg_overlap > REASM_MAX_NEG)
		return false; // too big minus

	size_t szcopy, szignore;
	szignore = (neg_overlap > reasm->size_present) ? neg_overlap - reasm->size_present : 0;
	if (szignore>=len) return true; // everyting is before the starting pos
	szcopy = len - szignore;
	neg_overlap -= szignore;
	if ((reasm->size_present - neg_overlap + szcopy) > reasm->size)
		return false; // buffer overflow
	// in case of seq overlap new data replaces old - unix behavior
	memcpy(reasm->packet + reasm->size_present - neg_overlap, payload + szignore, szcopy);
	if (szcopy>neg_overlap)
	{
		reasm->size_present += szcopy - neg_overlap;
		reasm->seq += (uint32_t)szcopy - neg_overlap;
	}
	return true;
}
bool ReasmHasSpace(t_reassemble *reasm, size_t len)
{
	return (reasm->size_present + len) <= reasm->size;
}
