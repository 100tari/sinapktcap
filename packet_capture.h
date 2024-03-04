#ifndef SINAPKTCAP_PACKET_CAPTURE_H
#define SINAPKTCAP_PACKET_CAPTURE_H

#include <sys/types.h>
#include <netinet/if_ether.h>
#include <stdint.h>

#define TOSTRING(X)             #X
#define COLOR_TXT(colr)         "\e["TOSTRING(colr)"m"

#define DRED                    COLOR_TXT(31)
#define DGRN                    COLOR_TXT(32)
#define DYEL                    COLOR_TXT(33)
#define DBLU                    COLOR_TXT(34)
#define DMGN                    COLOR_TXT(35)
#define DCYN                    COLOR_TXT(36)

#define NORM                    "\e[m"
#define BOLD                    "\e[1m"


#define errExit(msg)                                                        \
            { fprintf(stderr, msg);                                         \
            exit(EXIT_FAILURE); }

#define LOG(...)                                                              \
            {printf(__VA_ARGS__);                                             \
            if(file_fd!=NULL) fprintf(file_fd, __VA_ARGS__);} 

#define MAC_LEN                 6
#define IP_LEN                  4

#define CAPTURED_BUFFER_SIZE    1514

int             sinapktcap_init_capturing();
size_t          sinapktcap_capture_pkt(int, unsigned char*, size_t);
void            sinapktcap_print_ether_hdr(const unsigned char*);
void            sinapktcap_print_ip_hdr(const unsigned char*);
void            sinapktcap_print_tcp_hdr(const unsigned char*);
void            sinapktcap_print_hdrs(const unsigned char*, size_t);

#endif // SINAPKTCAP_PACKET_CAPTURE_H