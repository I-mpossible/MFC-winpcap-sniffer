#include "pcap.h"

typedef struct ip_address
{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;

}ip_address;

typedef struct mac_address
{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
	u_char byte5;
	u_char byte6;

}mac_address;

typedef struct ip_header
{
	u_char		ver_hrdlen;		// °æ±¾ºÅ(4 bits) + Ê×²¿³¤¶È(4 bits)
	u_char		tos;			// ·þÎñÀàÐÍ
	u_short		totallen;		// ×Ü³¤¶È
	u_short		identifier;	// ±êÊ¶
	u_short		flags_offset;	// ±êÖ¾(3 bits) + Æ¬Æ«ÒÆ(13 bits)
	u_char		ttl;			// Éú´æÊ±¼ä
	u_char		proto;			// ÉÏ²ãÐ­Òé
	u_short		checksum;		// Ê×²¿Ð£ÑéºÍ
	ip_address	srcaddr;		// Ô´µØÖ·
	ip_address	dstaddr;		// Ä¿µÄµØÖ·
	u_int		option_padding;	// Ñ¡ÏîºÍÌî³ä

}ip_header;


typedef struct arp_header
{
	u_short		hardtype;		// Ó²¼þÀàÐÍ
	u_short		prototype;		// Ð­ÒéÀàÐÍ
	u_char		hardlen;		// Ó²¼þ³¤¶È
	u_char		protolen;		// Ð­Òé³¤¶È
	u_short		op;				// ²Ù×÷Âë
	mac_address	srcmac;			// Ô´macµØÖ·
	ip_address	srcip;			// Ô´ipµØÖ·
	mac_address	dstmac;			// Ä¿µÄmacµØÖ·
	ip_address  dstip;			// Ä¿µÄipµØÖ·

}arp_header;

typedef struct udp_header
{
	u_short srcport;			// Ô´¶Ë¿Ú
	u_short dstport;			// Ä¿µÄ¶Ë¿Ú
	u_short	len;				// ³¤¶È
	u_short checksum;			// Ð£ÑéºÍ

}udp_header;

typedef struct tcp_header
{
	u_short		srcport;			// Ô´¶Ë¿Ú
	u_short		dstport;			// Ä¿µÄ¶Ë¿Ú
	u_long		seq;				// ÐòºÅ
	u_long		ack;				// È·ÈÏºÅ
	u_short		hdrlen_rsv_flags;	// Ê×²¿³¤¶È(4 bits) + ±£Áô(6 bits) + URG(1 bit) + ACK(1 bit) + PSH(1 bit) + RST(1 bit) + SYN(1 bit) + FIN(1 bit)
	u_short		win_size;			// ´°¿Ú´óÐ¡
	u_short		chksum;				// Ð£ÑéºÍ
	u_short		urg_ptr;			// ½ô¼±Ö¸Õë
	u_long		option;				// Ñ¡Ïî

}tcp_header;

typedef struct dns_header
{
	u_short		identifier;			// ±êÊ¶
	u_short		flags;				// ±êÖ¾
	u_short		questions;			// ²éÑ¯¼ÇÂ¼Êý
	u_short		answers;			// »Ø´ð¼ÇÂ¼Êý
	u_short		authority;			// ÊÚÈ¨»Ø´ð¼ÇÂ¼Êý
	u_short		additional;			// ¸½¼ÓÐÅÏ¢¼ÇÂ¼Êý

}dns_header;

typedef struct dns_query
{
	u_short type;					// ²éÑ¯ÀàÐÍ
	u_short classes;				// ²éÑ¯Àà

}dns_query;

typedef struct dns_answer
{
	u_short type;					// ÀàÐÍ
	u_short classes;				// Àà
	u_long	ttl;					// Éú´æÊ±¼ä

}dns_answer;

typedef struct icmp_header
{
	u_char	type;					// ÀàÐÍ
	u_char	code;					// ´úÂë
	u_short chksum;					// Ð£ÑéºÍ
	u_long  others;					// Ê×²¿ÆäËû²¿·Ö£¨ÓÉ±¨ÎÄÀàÐÍÀ´È·¶¨ÏàÓ¦ÄÚÈÝ£©

}icmp_header;

/* chaddr×Ö¶Îµ½option×Ö¶ÎÔÚdecodeDHCPÖÐ½âÎö */
typedef struct dhcp_header
{
	u_char	op;						// ±¨ÎÄÀàÐÍ
	u_char	htype;					// Ó²¼þÀàÐÍ
	u_char	hlen;					// Ó²¼þµØÖ·³¤¶È
	u_char	hops;					// ÌøÊý
	u_long	xid;					// ÊÂÎñID
	u_short secs;					// ¿Í»§Æô¶¯Ê±¼ä
	u_short flags;					// ±êÖ¾
	ip_address ciaddr;				// ¿Í»§»úIPµØÖ·
	ip_address yiaddr;				// ÄãµÄIPµØÖ·
	ip_address siaddr;				// ·þÎñÆ÷IPµØÖ·
	ip_address giaddr;				// Íø¹ØIPµØÖ·
//  u_char[16] chaddr;				// ¿Í»§Ó²¼þµØÖ·
//  u_char[64] sname;				// ·þÎñÆ÷Ö÷»úÃû
//  u_char[128] file;				// Æô¶¯ÎÄ¼þÃû
//  options(variable)				// Ñ¡Ïî£¨±ä³¤£©

}dhcp_header;

typedef struct packet_header
{
	mac_address		saddr;			// Ô´macµØÖ·
	mac_address		daddr;			// Ä¿µÄmacµØÖ·
	u_short			eth_type;		// ÒÔÌ«ÍøÖ¡ÀàÐÍ×Ö¶Î
	ip_header		*iph;			// ipÊ×²¿
	arp_header		*arph;			// arpÊ×²¿
	icmp_header     *icmph;			// icmpÊ×²¿
	udp_header		*udph;			// udpÊ×²¿
	tcp_header		*tcph;			// tcpÊ×²¿
	dns_header		*dnsh;			// dnsÊ×²¿
	u_char			*pkt_data;		// ÍêÕûÊý¾Ý°ü
	int				caplen;			// ²¶»ñÊý¾Ý°ü³¤¶È

}packet_header;



#pragma once
