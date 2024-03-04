#define _DEFAULT_SOURCE         /* for tcphdr struct */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <sys/socket.h>

#include <netinet/in.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
                     
#include "packet_capture.h"

#define MAC_FORMAT(X)           "%.2X-%.2X-%.2X-%.2X-%.2X-%.2X",X[0],X[1],X[2],X[3],X[4],X[5]
#define  IP_FORMAT(X)           "%d.%d.%d.%d", X->part1, X->part2, X->part3, X->part4

struct IP
{
    uint8_t part1;
    uint8_t part2;
    uint8_t part3;
    uint8_t part4;
}; 

static FILE* file_fd;

int 
sinapktcap_init_capturing()
{
    int sock_raw;
    if((sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
        errExit("socket initilizing failed! make sure you have root premision"); 

    if((file_fd = fopen("sniffer.log", "w+")) == 0)
        errExit("file initilizing failed!"); 

    return sock_raw;
}

size_t
sinapktcap_capture_pkt(int sock_fd, unsigned char* buf, size_t buf_size)
{
    if(buf==0)
        return -1;

    size_t recv_size;
    if((recv_size = recv(sock_fd, buf, buf_size, 0)) < 0)
        errExit("socket receiving failed!");

    return recv_size;
}

void
sinapktcap_print_ether_hdr(const unsigned char* pkt_buf)
{
    if(pkt_buf==0)
        return;

    struct ethhdr* eth = (struct ethhdr*) pkt_buf;

    short mac_str_len = MAC_LEN*3*sizeof(char);
    char eth_src_mac[MAC_LEN*3*sizeof(char)];
    char eth_dst_mac[MAC_LEN*3*sizeof(char)];
    char* eth_proto = (eth->h_proto==htons(ETH_P_IP)) ? "IP (0x0800)" : "unknown";                      /* ------- (0x----) */
    
    snprintf(eth_src_mac, MAC_LEN*3*sizeof(char), MAC_FORMAT(eth->h_source));
    snprintf(eth_dst_mac, MAC_LEN*3*sizeof(char), MAC_FORMAT(eth->h_dest)); 

    LOG(BOLD DYEL"[Ethernet Header]\n"NORM);
    LOG(DYEL"\t+ Source MAC:\t\t%s\n",              eth_src_mac)      
    LOG("\t+ Destination MAC:\t%s\n",               eth_dst_mac); 
    LOG("\t+ Type:\t\t\t%s\n"NORM,                  eth_proto);
}

void
sinapktcap_print_ip_hdr(const unsigned char* pkt_buf)
{
    if(pkt_buf==0)
        return;

    struct iphdr* ip = (struct iphdr*) (pkt_buf + sizeof(struct ethhdr));

    struct IP* ip_src = (struct IP*) (&ip->saddr);  
    struct IP* ip_dst = (struct IP*) (&ip->daddr);  

    short ip_str_len = IP_LEN*4*sizeof(char);
    char ip_src_ip[ip_str_len];
    char ip_dst_ip[ip_str_len];
    char* ip_version = (ip->version==4) ? "v4" : (ip->version==6) ? "v6" : "unknown";

    snprintf(ip_src_ip, ip_str_len, IP_FORMAT(ip_src));
    snprintf(ip_dst_ip, ip_str_len, IP_FORMAT(ip_dst));

    LOG(BOLD DGRN"[IP Header]\n"NORM);
    LOG(DGRN"\t+ Source IP:\t\t%s\n",                   ip_src_ip);
    LOG("\t+ Destination IP:\t%s\n",                    ip_dst_ip);
    LOG("\t+ IP Version:\t\t%s\n",                      ip_version);
    // LOG("\t+ Protocol:\t\t%d\n"NORM,                    ip->protocol);
}

void
sinapktcap_print_tcp_hdr(const unsigned char* pkt_buf)
{
    if(pkt_buf==0)
        return;
    
    struct iphdr* ip = (struct iphdr*) (pkt_buf + sizeof(struct ethhdr));

    struct tcphdr* tcp = (struct tcphdr*) (pkt_buf + ip->ihl*4 + sizeof(struct ethhdr));

    LOG(BOLD DCYN"[TCP Header]\n"NORM);
    LOG(DCYN"\t+ Source Port:\t\t%u\n",             ntohs(tcp->source));
    LOG("\t+ Destination Port:\t%u\n",              ntohs(tcp->dest));
}

void 
sinapktcap_print_hdrs(const unsigned char* pkt_buf, size_t pkt_buf_size)
{
     if(pkt_buf==0)
        return;

    struct ethhdr* eth = (struct ethhdr*) (pkt_buf);
    time_t t;

    if(ntohs(eth->h_proto) == ETH_P_IP)
    {
        time(&t);printf("\t\t\t%s ", ctime(&t));
        LOG(BOLD DRED"\t\t\tTCP Packet Captured:  %d Byte"NORM, (int)pkt_buf_size);
        LOG("\n\n");

        sinapktcap_print_ether_hdr(pkt_buf);
        sinapktcap_print_ip_hdr(pkt_buf);
        sinapktcap_print_tcp_hdr(pkt_buf);

        LOG(NORM "\n---------------------------------------------------------------------------\n");
    }
}