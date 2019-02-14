#include "mainArpHeader.h"

enum {
	BASIC = 1,
	START_MY,
	START_ROUTE,
	START_IPSCAN,
	START_SPOOF,
	START_RELAY,
	POPEN,
};

int popen_comm_func(char *cmd, char *buf, size_t buf_len);
int print_info_comm_func(char *name, u_char *ip, u_char *mac, int flag);
