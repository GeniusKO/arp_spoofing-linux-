CC = gcc
INC = mainArpSpoofing.h common_func.h mainArpHeader.h
LIBS = -lpcap -lpthread
CFLAGS = -pipe -O2 -W -Wall -D_GNU_SOURCE
TARGET = arp_Spoofing
OBJECTS = mainArpSpoofing.o getAdapterInfo.o common_func.o getTargetIpScan.o arpPacketRelay.o targetSniffing.o

all : $(TARGET)
$(TARGET): $(OBJECTS)
		$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

clean :
		rm *.o arp_Spoofing
