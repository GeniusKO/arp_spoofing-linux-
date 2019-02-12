#/bin/sh

gcc -o arp_Spoofing mainArpSpoofing.c getAdapterInfo.c getTargetIpScan.c common_func.c arpPacketRelay.c -lpcap -lpthread
