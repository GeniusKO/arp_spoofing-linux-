#include "mainArpSpoofing.h" 

pcap_t *fp;
int dupFlag = 0;
int setExitFlag = 0;
int target_count = 0;
int broadcast_count = 0;
struct TargetInfo target_array[BROADCAST_NUM];
struct TargetInfo *head;

struct arg_struct {	
	char setIpAddress[IP_ADDR_LEN];
	char setMacAddress[ETHER_ADDR_LEN];
	char setRouteAddress[IP_ADDR_LEN];
};

typedef struct arg_struct ipscan;

enum {
	DUP_FOUND = 1
};

int PrintTargetArray();

void *GetIpScan_ThreadRun(void *arguments) {
	u_char *brod_packet = (u_char *)malloc(sizeof(u_char) * ARP_HDR_LEN);
	ipscan *args = (ipscan *)arguments;
	struct libnet_ethernet_hdr *eh;
	struct libnet_arp_hdr *ah;

	int i = 0, j = 0, result = 0;

	while(1) {
		eh = (struct libnet_ethernet_hdr *)brod_packet;
		ah = (struct libnet_arp_hdr *)brod_packet;

		for(i = 0; i < ETHER_ADDR_LEN; i++) *(brod_packet + i) = 0xff;
		for(j = 0; i < ETHER_ADDR_LEN * 2; i++, j++) *(brod_packet + i) = args->setMacAddress[j];
		brod_packet += sizeof(eh->ether_dhost) + sizeof(eh->ether_shost);
		*(brod_packet + 0) = 0x08;
		*(brod_packet + 1) = 0x06;
		brod_packet += sizeof(eh->ether_type);
		for(i = 0; i < 6; i++) {
			switch (i) { 
				case 0:
					*(brod_packet + i) = 0x00; break;
				case 1:
					*(brod_packet + i) = 0x01; break;
				case 2:
					*(brod_packet + i) = 0x08; break;
				case 3:
					*(brod_packet + i) = 0x00; break;
				case 4:
					*(brod_packet + i) = 0x06; break;
				case 5:
					*(brod_packet + i) = 0x04; break;
			}
		}
		brod_packet += sizeof(ah->ar_hrd) + sizeof(ah->ar_pro) + sizeof(ah->ar_hln) + sizeof(ah->ar_pln);
		*(brod_packet + 1) = ARPOP_REQUEST;
		brod_packet += sizeof(ah->ar_op);
		for(i = 0; i < ETHER_ADDR_LEN; i++) *(brod_packet + i) = args->setMacAddress[i];
		for(j = 0; i < ETHER_ADDR_LEN + IP_ADDR_LEN; i++, j++) *(brod_packet + i) = args->setIpAddress[j];
		brod_packet += sizeof(ah->ar_sha) + sizeof(ah->ar_spa);
		for(i = 0; i < ETHER_ADDR_LEN; i++) *(brod_packet + i) = 0x00;
		for(j = 0; i < ETHER_ADDR_LEN + IP_ADDR_LEN - 1; i++, j++) *(brod_packet + i) = args->setIpAddress[j];
		brod_packet += sizeof(ah->ar_tha) + 3;
		for(i = 1; i < BROADCAST_NUM; i++) {
			*(brod_packet) = i;
			brod_packet -= sizeof(*eh) + sizeof(*ah) - 1;
			if((result = pcap_inject(fp, brod_packet, ARP_HDR_LEN)) < 0) { printf("pcap_inject() Error %d\n", result); goto out; }
			brod_packet += sizeof(*eh) + sizeof(*ah) - 1;
		}
		brod_packet -= sizeof(*eh) + sizeof(*ah) - 1;
		broadcast_count++;
		sleep(6);
		if(broadcast_count == 5) goto out;
	}
out:
	free(brod_packet);
	PrintTargetArray();
	setExitFlag = EXIT_OK;
	pthread_exit(NULL);
}

int GetIpScan_Thread(u_char *setIp, u_char *setMac, u_char *setRoute, pcap_t *return_fp) {
	pthread_t pThread;
	ipscan *args = (ipscan *)malloc(sizeof(ipscan));
	int threadErr, count;
	fp = return_fp;

	for(count = 0; count < IP_ADDR_LEN; count++) args->setIpAddress[count] = *(setIp + count);
	for(count = 0; count < ETHER_ADDR_LEN; count++) args->setMacAddress[count] = *(setMac + count);
	for(count = 0; count < IP_ADDR_LEN; count++) args->setRouteAddress[count] = *(setRoute + count);

	if((threadErr = pthread_create(&pThread, NULL, GetIpScan_ThreadRun, (void *)args)) < 0) { 
		printf("Thread Err = %d\n", threadErr);
		return -1;
	}

	return 1;
}

int TargetReplyScan(struct libnet_arp_hdr *ah) {
	int i = 0;
	if(target_count == 0) {
		for(i = 0; i < IP_ADDR_LEN; i++) target_array[target_count].target_ip[i] = ah->ar_spa[i];
		for(i = 0; i < ETHER_ADDR_LEN; i++) target_array[target_count].target_mac[i] = ah->ar_sha[i];
		target_array[target_count].target_number = target_count + 1;
		target_count++;
	} else {
		head = target_array;
		while(head) {
			if(!strcasecmp((const char *)head->target_ip, (const char *)ah->ar_spa)) dupFlag = DUP_FOUND;
			else head = head->next;
			if(dupFlag == DUP_FOUND) break;
		}
		if(dupFlag != DUP_FOUND) {
			for(i = 0; i < IP_ADDR_LEN; i++) target_array[target_count].target_ip[i] = ah->ar_spa[i];
			for(i = 0; i < ETHER_ADDR_LEN; i++) target_array[target_count].target_mac[i] = ah->ar_sha[i];
			target_array[target_count].target_number = target_count + 1;
			target_count++;
		}
	} 
	return 0;
}

int PrintTargetArray() {
	int i = 0, j = 0;
	char ipbuff[32] = {0,};

	for(i = 0; i < target_count; i ++) {
		printf("%02d. IP : %s MAC : ", target_array[i].target_number, inet_ntop(AF_INET, &target_array[i].target_ip, ipbuff, sizeof(ipbuff)));
		for(j = 0; j < ETHER_ADDR_LEN; j++) {
			if(j == 5) printf("%02X\n", target_array[i].target_mac[j]);
			else printf("%02X:", target_array[i].target_mac[j]);
		}
	}

	return 0;
}

int setPcapExitFlag() {
	return setExitFlag;
}
int setTargetCount() {
	return target_count;
}

int setTargetNumber(int sel_number, u_char *select_target_ip, u_char *select_target_mac) {
	int i = 0, count = 0;
	count = sel_number - 1;
	for(i = 0; i < IP_ADDR_LEN; i++) *(select_target_ip + i) = target_array[count].target_ip[i];
	for(i = 0; i < ETHER_ADDR_LEN; i++) *(select_target_mac + i) = target_array[count].target_mac[i];

	return 1;
}
