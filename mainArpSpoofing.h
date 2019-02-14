#include "mainArpHeader.h"

enum {
	EXIT_OK = 1
};

typedef unsigned char u_char;

struct TargetInfo {
	struct TargetInfo *next;
	u_char target_ip[IP_ADDR_LEN];
	u_char target_mac[ETHER_ADDR_LEN];	
	int target_number;
};

typedef struct ArpSpoofStruct {
	u_char getMyIp[IP_ADDR_LEN];
	u_char getMyMac[ETHER_ADDR_LEN];
	u_char getRouteIp[IP_ADDR_LEN];
	u_char getRouteMac[ETHER_ADDR_LEN];
	u_char getTargetIp[IP_ADDR_LEN];
	u_char getTargetMac[ETHER_ADDR_LEN];
}_SPOOF;

int GetIpScan_Thread(u_char *setIp, u_char *setMac, u_char *setRoute, pcap_t *return_fp);
//int GetArpRelay_Thread(void *arp, pcap_t *return_fp);

int TargetReplyScan(struct libnet_arp_hdr *ah);
int GetGateway_info(u_char *getRouteIp, u_char *getRouteMac);
int GetMyAdapter_info(char *device_name, u_char *getMyIp, u_char *getMyMac);
int setPcapExitFlag();
int setTargetCount();
int setTargetNumber(int sel_number, u_char *select_target_ip, u_char *select_target_mac);

void SetArpRelayPcapHandle(pcap_t *return_fp);
void SetArpSniffPcapHandle(pcap_t *return_fp);
void *GetArpRelay_ThreadRun(void *arguments);
void *TargetSniffing_ThreadRun(void *arguments);
