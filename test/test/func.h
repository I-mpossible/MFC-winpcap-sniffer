#pragma once
#include "pcap.h"
#include "remote-ext.h"
#include "Afxtempl.h"
#include "packet_header.h"
#define PCAP_ERRBUFF_SIZE	50


/* ¶ÑÎÄ¼þÎÄ¼þÃû */
char filename[50];

/* È«¾Ö±äÁ¿¿Ø¼þ */
CListCtrl *pList1;
CComboBox *pDevList;
CComboBox *pProtocolList;
CWnd *pStart;
CWnd *pStop;
CTreeCtrl *pTree;


/* È«¾Ö±äÁ¿£¬´æ·ÅÉè±¸ÐÅÏ¢ */
pcap_if_t *alldevs, *d;

/* È«¾Ö±äÁ¿errbuf£¬´æ·Å´íÎóÐÅÏ¢ */
char errbuf[PCAP_ERRBUF_SIZE];

/* È«¾Ö±äÁ¿adhandle */
pcap_t *adhandle;

/* Éè±¸ÁÐ±íÐÐÁÐ£¬±àºÅ */
int list_rows = -1;
int list_cols = 0;
int list_count = 0;

/*包计数初始化*/
int tcpcount = 0;
int udpcount = 0;
int icmpcount = 0;

/* Á´±í£¬´¢´æ±¨ÎÄµÄÊ×²¿ */
CList<packet_header, packet_header> linklist;

/* Ïß³Ì´¦Àíº¯Êý */
UINT capture_thread(LPVOID pParam);

/* ²¶»ñ´¦Àíº¯Êý */
void packet_handler(u_char *dumpfile, const struct pcap_pkthdr *header, const u_char *pkt_data);

/* ´æ´¢±¨ÎÄÊ×²¿	*/
void saveFrame(const u_char *pkt_data, int offset);		//ok
void saveIP(const u_char *pkt_data, int offset);		//ok
void saveARP(const u_char *pkt_data, int offset);		//ok
void saveUDP(const u_char *pkt_data, int offset);		//ok
void saveTCP(const u_char *pkt_data, int offset);		//ok
void saveICMP(const u_char *pkt_data, int offset);		//ok
void saveDNS(const u_char *pkt_data, int offset);		//ok


/* ½âÎö±¨ÎÄÊ×²¿ */
void decodeFrame(mac_address *saddr, mac_address *daddr, u_short *eth_type, HTREEITEM *hParent);
void decodeIP(ip_header *iph, HTREEITEM *hParent);
void decodeARP(arp_header *arph, HTREEITEM *hParent);
void decodeUDP(udp_header *udph, HTREEITEM *hParent);
void decodeTCP(tcp_header *tcph, HTREEITEM *hParent);
void decodeDNS(u_char *pkt_data, int offset, dns_header *dnsh, HTREEITEM *hParent);			// offsetÎªµ½dnsÊ×²¿µÄÆ«ÒÆÁ¿
void decodeHTTP(u_char *pkt_data, int offset, HTREEITEM *hParent);							// offsetÎªµ½HTTP±¨ÎÄµÄÆ«ÒÆÁ¿
void decodeICMP(icmp_header *icmph, HTREEITEM *hParent);
void decodeDHCP(u_char *pkt_data, int offset, HTREEITEM *hParent);							// offsetÎªµ½DHCP±¨ÎÄµÄÆ«ÒÆÁ¿


/* ÓòÃû×ª»» ½«¹æ¶¨¸ñÊ½µÄname2×ª»»ÎªÓòÃûname1 */
void translateName(char *name1, const char *name2);

/* DNS×ÊÔ´¼ÇÂ¼Êý¾Ý²¿·Ö×ª»» ½«´øÓÐÖ¸Õëc0µÄµØÖ·data2×ª»»ÎªµØÖ·data1 offsetÎªµ½dnsÊ×²¿µÄÆ«ÒÆÁ¿*/
void translateData(u_char *pkt_data, int offset, char *data1, char *data2, int data2_len);

/* ÅÐ¶ÏdataÖÐÓÐÎÞÖ¸Õë0xc0,²¢·µ»ØÖ¸ÕëÔÚdataÖÐµÄÎ»ÖÃ*/
int isNamePtr(char *data);
