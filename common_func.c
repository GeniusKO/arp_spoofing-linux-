#include "common_func.h"

int popen_comm_func(char *cmd, char *buf, size_t buf_len) {
    FILE *fp = NULL;

    memset(buf, 0x00, buf_len);

    fp = popen(cmd, "r");
    if (fp == NULL) {
        perror("errno : ");
        exit(0);
    }

    char *p = buf;
    int len = 0;
    int remain = buf_len;

    while (!feof(fp) && remain > 0)  {
        len = fread(p, 1, remain, fp);
        p+=len;
        remain -= len;
    }
    *p = 0;
    pclose(fp);

    return len;
}

int print_info_comm_func(char *name, u_char *ip, u_char *mac, int flag) {
	int i;
	char ipbuff[32] = {0,};
	
	switch (flag) {
		case BASIC:
			printf("%s Ip Address : %s %s Mac Address : ", name, inet_ntop(AF_INET, ip, ipbuff, sizeof(ipbuff)), name);
			for(i = 0; i < ETHER_ADDR_LEN; i++) {
				if(i == 5) printf("%02X\n", mac[i]);
				else printf("%02X:", mac[i]);
			}
			break;
		case START_MY:
			printf("Start Get My Adapter Information ......................... Success\n");
			break;
		case START_ROUTE:
			printf("Start Get Router Information ............................. Success\n");
			break;
		case START_IPSCAN:
			printf("Start Target IP Scanning Wait A Moment ...........................\n");
			break;
		case START_SPOOF:
			printf("Target Spoofing Success and Start Target Sniffer ......... Success\n");
			break;
		case START_RELAY:
			printf("Start ARP Request and ARP Reply Relay .................... Success\n");
			break;
		case POPEN:
			printf("Start Set IP Forwarding net.ipv4.ip_forward = 1 .......... Success\n");
			break;
	}

	return 0;
}
