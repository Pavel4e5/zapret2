#pragma once

#include <time.h>

#define CTRACK_T_SYN	60
#define CTRACK_T_FIN	60
#define CTRACK_T_EST	300
#define CTRACK_T_UDP	60

// SYN - SYN or SYN/ACK received
// ESTABLISHED - any except SYN or SYN/ACK received
// FIN - FIN or RST received
typedef enum {SYN=0, ESTABLISHED, FIN} t_connstate;

typedef struct
{
	time_t t_last, t_start;

	uint64_t pcounter_orig, pcounter_reply;	// packet counter
	uint64_t pdcounter_orig, pdcounter_reply; // data packet counter (with payload)
	uint64_t pbcounter_orig, pbcounter_reply; // transferred byte counter. includes retransmissions. it's not the same as relative seq.
	uint32_t pos_orig, pos_reply;		// TCP: seq_last+payload, ack_last+payload  UDP: sum of all seen payload lenghts including current
	uint32_t uppos_orig, uppos_reply;	// max seen position. useful to detect retransmissions
	uint32_t uppos_orig_prev, uppos_reply_prev; // previous max seen position. useful to detect retransmissions
	uint32_t seq_last, ack_last;		// TCP: last seen seq and ack  UDP: sum of all seen payload lenghts NOT including current

	// tcp only state, not used in udp
	t_connstate state;
	uint32_t seq0, ack0;			// starting seq and ack
	uint16_t winsize_orig, winsize_reply;	// last seen window size
	uint8_t scale_orig, scale_reply;	// last seen window scale factor. SCALE_NONE if none
	uint32_t winsize_orig_calc, winsize_reply_calc;	// calculated window size
	uint16_t mss_orig, mss_reply;
} t_ctrack_position;
