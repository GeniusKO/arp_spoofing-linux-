#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <libnet.h>
#include <ifaddrs.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_ether.h>
#include <sys/socket.h>
#include <pthread.h>

#define IP_ADDR_LEN 4
#define ARP_HDR_LEN 42
#define BROADCAST_NUM 255

enum {
	EXIT_OK = 1
};

typedef unsigned char u_char;

struct AdapterInfo {
	u_char getMyIpAddress[IP_ADDR_LEN];
	u_char getRouteIpAddress[IP_ADDR_LEN];
	u_char getMyMacAddress[ETHER_ADDR_LEN];
	u_char getRouteMacAddress[ETHER_ADDR_LEN];
};

struct TargetInfo {
	struct TargetInfo *next;
	u_char target_ip[IP_ADDR_LEN];
	u_char target_mac[ETHER_ADDR_LEN];	
	int target_number;
};

int GetIpScan_Thread(char *setIp, char *setMac, char *setRoute, pcap_t *return_fp);
int GetArpRelay_Thread(u_char *setMyIp, u_char *setMyMac, u_char *setRouteIp, u_char *setRouteMac, u_char *setTargetIp, u_char *setTargetMac, pcap_t *return_fp);
int TargetReplyScan(struct libnet_arp_hdr *ah, struct AdapterInfo *info);
int GetGateway_info(u_char *getRouteIp, u_char *getRouteMac);
int GetMyAdapter_info(char *device_name, u_char *getMyIp, u_char *getMyMac);
int setPcapExitFlag();
int setTargetCount();
void setTargetNumber(int sel_number, u_char *select_target_ip, u_char *select_target_mac);
