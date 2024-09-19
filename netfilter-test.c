#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <errno.h>
#include <string.h>

#include <libnetfilter_queue/libnetfilter_queue.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

static u_int32_t print_pkt(struct nfq_data *tb)
{
    int id = 0;
    struct nfqnl_msg_packet_hdr *ph;
    struct nfqnl_msg_packet_hw *hwph;
    u_int32_t mark, ifi;
    int ret;
    unsigned char *data;

    ph = nfq_get_msg_packet_hdr(tb);
    if (ph) {
        id = ntohl(ph->packet_id);
        printf("hw_protocol=0x%04x hook=%u id=%u ", ntohs(ph->hw_protocol), ph->hook, id);
    }

    hwph = nfq_get_packet_hw(tb);
    if (hwph) {
        int i, hlen = ntohs(hwph->hw_addrlen);

        printf("hw_src_addr=");
        for (i = 0; i < hlen-1; i++)
            printf("%02x:", hwph->hw_addr[i]);
        printf("%02x ", hwph->hw_addr[hlen-1]);
    }

    mark = nfq_get_nfmark(tb);
    if (mark)
        printf("mark=%u ", mark);

    ifi = nfq_get_indev(tb);
    if (ifi)
        printf("indev=%u ", ifi);

    ifi = nfq_get_outdev(tb);
    if (ifi)
        printf("outdev=%u ", ifi);
    ifi = nfq_get_physindev(tb);
    if (ifi)
        printf("physindev=%u ", ifi);

    ifi = nfq_get_physoutdev(tb);
    if (ifi)
        printf("physoutdev=%u ", ifi);

    ret = nfq_get_payload(tb, &data);
    if (ret >= 0)
        printf("payload_len=%d\n", ret);

    fputc('\n', stdout);

    return id;
}

void dump(unsigned char* buf, int size) {
    int i;
    for (i = 0; i < size; i++) {
        if (i != 0 && i % 16 == 0)
            printf("\n");
        printf("%02X ", buf[i]);
    }
    printf("\n");
}


//IP, TCP, HTTP로 우선 필터링을 하고, 80번 포트를 사용할 때 호스트를 파싱해서 비교 후 락을 설정한 후에 리턴
//strstr 함수 및 /r/n을 활용
static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
          struct nfq_data *nfa, void *data)
{
    u_int32_t id = print_pkt(nfa);
    printf("entering callback\n");

    int payload_len;
    unsigned char *payload;
    char *blocked_host = (char *)data;

    payload_len = nfq_get_payload(nfa, &payload);
    if (payload_len >= sizeof(struct iphdr)) {
        struct iphdr *ip_header = (struct iphdr *)payload;

        if (ip_header->version != 4)
            return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

        if (ip_header->protocol == IPPROTO_TCP) {
            int ip_header_length = ip_header->ihl * 4;
            if (payload_len < ip_header_length + sizeof(struct tcphdr))
                return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

            struct tcphdr *tcp_header = (struct tcphdr *)(payload + ip_header_length);
            int tcp_header_length = tcp_header->doff * 4;
            int data_offset = ip_header_length + tcp_header_length;

            if (ntohs(tcp_header->dest) == 80 || ntohs(tcp_header->source) == 80) {
                if (payload_len > data_offset) {
                    char *http_payload = (char *)(payload + data_offset);
                    http_payload[payload_len - data_offset] = '\0';

                    char *host_ptr = strstr(http_payload, "Host: ");
                    if (host_ptr) {
                        host_ptr += 6;
                        char *end_ptr = strstr(host_ptr, "\r\n");
                        if (end_ptr) {
                            int host_length = end_ptr - host_ptr;
                            if (host_length < 256) {
                                char host[256];
                                strncpy(host, host_ptr, host_length);
                                host[host_length] = '\0';
                                printf("HTTP Host: %s\n", host);

                                if (strcasecmp(host, blocked_host) == 0) {
                                    return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <host>\n", argv[0]);
        exit(1);
    }

    char *blocked_host = argv[1];

    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));

    printf("opening library handle\n");
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        nfq_close(h);
        exit(1);
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        nfq_close(h);
        exit(1);
    }

    printf("binding this socket to queue '0'\n");
    qh = nfq_create_queue(h,  0, &cb, blocked_host);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        nfq_close(h);
        exit(1);
    }

    printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        nfq_destroy_queue(qh);
        nfq_close(h);
        exit(1);
    }

    fd = nfq_fd(h);

    printf("Waiting for packets...\n");
    while (1) {
        rv = recv(fd, buf, sizeof(buf), 0);
        if (rv >= 0) {
            printf("pkt received\n");
            nfq_handle_packet(h, buf, rv);
            continue;
        }

        if (rv < 0 && errno == ENOBUFS) {
            printf("losing packets!\n");
            continue;
        }
        perror("recv failed");
        break;
    }

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);

    printf("closing library handle\n");
    nfq_close(h);

    return 0;
}

