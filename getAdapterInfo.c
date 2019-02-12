#include "mainArpSpoofing.h"

#define BUFSIZE 8192

struct gw_info {
    uint32_t ip;
    char mac[ETHER_ADDR_LEN];
};

int GetMyAdapter_info(char *device_name, u_char *getMyIp, u_char *getMyMac) {
	struct ifaddrs *ifaddr, *ifa;
	struct sockaddr *mac_addr, *ip_addr;	
	unsigned char *ptr;
	int count = 0;

	if(getifaddrs(&ifaddr) < 0) {
		printf("Error : getifaddrs()\n");
		return 0;
	}

	for(ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {	
		if(ifa->ifa_addr == NULL) continue;
		if(ifa->ifa_addr->sa_family == AF_INET && !strncmp(ifa->ifa_name, device_name, strlen(device_name))) {
			ip_addr = (struct sockaddr *)(ifa->ifa_addr);
			ptr = (unsigned char *)ip_addr->sa_data + 2;
			for(count = 0; count < 4; count++) *(getMyIp + count) = *(ptr + count);
		}
		if(ifa->ifa_addr->sa_family == AF_PACKET && !strncmp(ifa->ifa_name, device_name, strlen(device_name))) {
			mac_addr = (struct sockaddr *)(ifa->ifa_addr);
			ptr = (unsigned char *)mac_addr->sa_data + 10;
			for(count = 0; count < ETHER_ADDR_LEN; count++) *(getMyMac + count) = *(ptr + count);
		}
	}

	freeifaddrs(ifaddr);
	return 0;
}

int send_req(int sock, char *buf, size_t nlseq, size_t req_type) {
	struct nlmsghdr *nlmsg;
    memset(buf, 0, BUFSIZE);
    nlmsg = (struct nlmsghdr *)buf;

    nlmsg->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    nlmsg->nlmsg_type = req_type;
    nlmsg->nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST;
    nlmsg->nlmsg_seq = nlseq++;
    nlmsg->nlmsg_pid = getpid();

    if (send(sock, buf, nlmsg->nlmsg_len, 0) < 0) return -1;
    return nlseq;
}

int read_res(int sock, char *buf, size_t nlseq) {
	struct nlmsghdr *nlmsg;
    int len;
    size_t total_len = 0;

    do {
        len = recv(sock, buf, BUFSIZE - total_len, 0);

        if (len < 0) return -1;

        nlmsg = (struct nlmsghdr *)buf;

        if (NLMSG_OK(nlmsg, len) == 0) return -1;
        if (nlmsg->nlmsg_type == NLMSG_ERROR) return -1;
        if (nlmsg->nlmsg_type == NLMSG_DONE) break;
        buf += len;
        total_len += len;
        if ((nlmsg->nlmsg_flags & NLM_F_MULTI) == 0) break;
    } while (nlmsg->nlmsg_seq != nlseq || nlmsg->nlmsg_pid != getpid());
    return total_len;
}

void parse_route(struct nlmsghdr *nlmsg, void *gw) {
	struct rtmsg *rtmsg;
    struct rtattr *attr;
    uint32_t gw_tmp;
    size_t len;
    struct gw_info *info;

    info = (struct gw_info *)gw;
    rtmsg = (struct rtmsg *)NLMSG_DATA(nlmsg);

    if (rtmsg->rtm_family != AF_INET || rtmsg->rtm_table != RT_TABLE_MAIN)
        return;

    attr = (struct rtattr *)RTM_RTA(rtmsg);
    len = RTM_PAYLOAD(nlmsg);

    for (; RTA_OK(attr, len); attr = RTA_NEXT(attr, len)) {
        if (attr->rta_type != RTA_GATEWAY) continue;

        info->ip = *(uint32_t *)RTA_DATA(attr);
        break;
    }
}

void parse_neigh(struct nlmsghdr *nlmsg, void *gw) {
    struct ndmsg *ndmsg;
    struct rtattr *attr;
    size_t len;
    char mac[ETH_ALEN];
    uint32_t ip = 0;
    struct gw_info *info;

    info = (struct gw_info *)gw;
    ndmsg = (struct ndmsg *)NLMSG_DATA(nlmsg);

    if (ndmsg->ndm_family != AF_INET) return;

    attr = (struct rtattr *)RTM_RTA(ndmsg);
    len = RTM_PAYLOAD(nlmsg);

    for (; RTA_OK(attr, len); attr = RTA_NEXT(attr, len)) {
        if (attr->rta_type == NDA_LLADDR) memcpy(mac, RTA_DATA(attr), ETH_ALEN);
        if (attr->rta_type == NDA_DST) ip = *(uint32_t *)RTA_DATA(attr);
    }

    if (ip && ip == info->ip) memcpy(info->mac, mac, ETH_ALEN);
}

void parse_response(char *buf, size_t len, void (cb)(struct nlmsghdr *, void *), void *arg) {
    struct nlmsghdr *nlmsg;
    nlmsg = (struct nlmsghdr *)buf;
    for (; NLMSG_OK(nlmsg, len); nlmsg = NLMSG_NEXT(nlmsg, len)) cb(nlmsg, arg);
}

void getChangeIp(char *ip_addr, u_char *ip) {
	int tmp;
	int i, j;
	int cnt = 0;
	for (j = 0; j < 4; j++) {
		tmp = 0;
		for (i = cnt; i < 16; i++) {
			if (isdigit(*(ip_addr + i))) {
				tmp *= 10;
				tmp += *(ip_addr + i) - '0';
			}
			else
				break;
		}
		cnt = i + 1;
		sprintf(&ip[j], "%c", tmp);
	}
}

int GetGateway_info(u_char *getRouteIp, u_char *getRouteMac) {
    int sock = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
	int count = 0;
    char buf[BUFSIZE];
	char ipbuff[32] = {0,};
    size_t nlseq = 0;
    size_t msg_len;
	struct gw_info gw;

    if (sock <= 0) return -1;

    nlseq = send_req(sock, buf, nlseq, RTM_GETROUTE);
    msg_len = read_res(sock, buf, nlseq);

    if (msg_len <= 0) return -1;

    parse_response(buf, msg_len, &parse_route, &gw);

    nlseq = send_req(sock, buf, nlseq, RTM_GETNEIGH);
    msg_len = read_res(sock, buf, nlseq);

    if (msg_len <= 0) return -1;

    parse_response(buf, msg_len, &parse_neigh, &gw);

	if(inet_ntop(AF_INET, &gw.ip, ipbuff, sizeof(ipbuff)) == NULL) return -1;
	else getChangeIp(ipbuff, getRouteIp);
	if(gw.mac) for(count = 0; count < ETHER_ADDR_LEN; count++) *(getRouteMac + count) = gw.mac[count];
	return 0;
}

