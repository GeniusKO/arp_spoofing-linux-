#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

#define IPV4PRO_TCP 0x06

#define HTTP_PORT 0x50
