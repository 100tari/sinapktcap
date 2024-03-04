#include "packet_capture.h"

int
main()
{
    int sock_raw; 
    unsigned char buf[CAPTURED_BUFFER_SIZE];
    size_t pkt_size;

    sock_raw = sinapktcap_init_capturing();
    while(1)
    {
        pkt_size = sinapktcap_capture_pkt(sock_raw, buf, CAPTURED_BUFFER_SIZE);
        sinapktcap_print_hdrs(buf, pkt_size);
    }

    return 0;
}