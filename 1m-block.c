
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include <string.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <sys/time.h>  // for gettimeofday
#include <search.h>


typedef struct {
	#  if __BYTE_ORDER == __LITTLE_ENDIAN
    uint8_t ihl:4;
    uint8_t version:4;
	#  endif

	#  if __BYTE_ORDER == __BIG_ENDIAN
    uint8_t version:4;
    uint8_t ihl:4;
	#  endif
    //uint8_t version_and_ihl;

    uint8_t type_of_service;
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_and_fragment_offset;
    uint8_t time_to_live;
    uint8_t protocol;
    uint16_t header_checksum;
    uint32_t s_addr;
    uint32_t d_addr;
} IpHdr;

typedef struct{
    u_int16_t s_port;
    u_int16_t d_port;
    u_int32_t seq_num;
    u_int32_t ack_num;

#  if __BYTE_ORDER == __LITTLE_ENDIAN
    u_int8_t reserved:4;
    u_int8_t offset:4;
#  endif

#  if __BYTE_ORDER == __BIG_ENDIAN
    u_int8_t offset:4;
    u_int8_t reserved:4;
#  endif

    u_int8_t flags;
#  define FIN  0x01
#  define SYN  0x02
#  define RST  0x04
#  define PUSH 0x08
#  define ACK  0x10
#  define URG  0x20

    u_int16_t window;
    u_int16_t checksum;
    u_int16_t urgent_pointer;
} TcpHdr;


#define MAX_DOMAIN 1000000

void load_domains(const char *filename) {
    struct timeval start, end;
    gettimeofday(&start, NULL);

    FILE *fp = fopen(filename, "r");
    if (!fp) {
        perror("file open failed");
        exit(1);
    }

    if (hcreate(MAX_DOMAIN) == 0) {
        perror("hcreate failed");
        exit(1);
    }

    char line[256];
    int count = 0;
	while (fgets(line, sizeof(line), fp)) 	{
        line[strcspn(line, "\r\n")] = '\0'; // remove newline

        char *comma = strchr(line, ',');
        if (!comma || !*(comma + 1)) {
            continue; // skip malformed line
        }

        char *domain = strdup(comma + 1); // skip past comma
        if (!domain) {
            perror("strdup failed");
            exit(1);
        }

        ENTRY e = { .key = domain, .data = (void *)1 };
        hsearch(e, ENTER);
        count++;
    }

    gettimeofday(&end, NULL);
    long elapsed = (end.tv_sec - start.tv_sec) * 1000000L +
                   (end.tv_usec - start.tv_usec);
    printf("Loaded %d domains in %ld microseconds (%.3f seconds)\n", count, elapsed, elapsed / 1000000.0);

}

void print_memory_usage() {
    FILE *fp = fopen("/proc/self/status", "r");
    if (!fp) return;

    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "VmRSS:", 6) == 0 || strncmp(line, "VmSize:", 7) == 0) {
            printf("%s", line);
        }
    }
    fclose(fp);
}

/* returns packet id */
static uint32_t print_pkt (struct nfq_data *tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	uint32_t mark, ifi, uid, gid;
	int ret;
	unsigned char *data, *secdata;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		printf("hw_protocol=0x%04x hook=%u id=%u ",
			ntohs(ph->hw_protocol), ph->hook, id);
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

	if (nfq_get_uid(tb, &uid))
		printf("uid=%u ", uid);

	if (nfq_get_gid(tb, &gid))
		printf("gid=%u ", gid);

	ret = nfq_get_secctx(tb, &secdata);
	if (ret > 0)
		printf("secctx=\"%.*s\" ", ret, secdata);

	ret = nfq_get_payload(tb, &data);
	if (ret >= 0)
		printf("payload_len=%d ", ret);
	fputc('\n', stdout);

	return id;
}


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	uint32_t id = print_pkt(nfa);
	printf("entering callback\n");

	unsigned char *payload;
	int ret = nfq_get_payload(nfa, &payload);

	IpHdr *ip_hdr = (IpHdr *)payload;
	
	if (ip_hdr->protocol != 6) return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
	
	TcpHdr *tcp_hdr = (TcpHdr *)(payload + (ip_hdr->ihl * 4));
	unsigned char *http = (unsigned char *)(payload + (ip_hdr->ihl * 4) + (tcp_hdr->offset * 4));
    int http_len = ret - (ip_hdr->ihl * 4) - (tcp_hdr->offset * 4);


	if(ntohs(tcp_hdr->d_port) == 80 && strncmp(http, "GET", 3) == 0) {
		char *site = memmem(http, http_len, "Host: ", 6);

		if (site) {

			// exclude (www.)google.com
            char *host_start = site + 6;
			while ((host_start - (char *)http < http_len) && (*host_start == ' ' || *host_start == '\t')) {
        		host_start++;
			}

            char *host_end = memchr(host_start, '\r', http_len - (host_start - (char *)http));
            
            if (host_end) {
                int host_len = host_end - (host_start);
                char domain[256] = {0};

                if (host_len < sizeof(domain)) {
                    strncpy(domain, host_start, host_len);
                    domain[host_len] = '\0';

					char *normalized = domain;
					if (strncmp(domain, "www.", 4) == 0) {
						normalized += 4;
					}

                    struct timeval t1, t2;
                    gettimeofday(&t1, NULL);

                    ENTRY e = { .key = normalized, .data = (void *)1 };
                    ENTRY *found = hsearch(e, FIND);

                    gettimeofday(&t2, NULL);
					long us = (t2.tv_sec - t1.tv_sec) * 1000000L + (t2.tv_usec - t1.tv_usec);


                    if (found) {
						printf("🔒 BLOCKED domain: %s (Lookup time: %ld μs)\n", domain, us);
                        return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
                    } else {
						printf("✅ ALLOWED domain: %s (Lookup time: %ld μs)\n", domain, us);
					}
                }
            }
		}
	}
	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	int fd;
	int rv;
	uint32_t queue = 0;
	char buf[4096] __attribute__ ((aligned));

	if (argc != 2) {
		fprintf(stderr, "syntax : 1m-block <site list file>\n");
		fprintf(stderr, "sample : 1m-block top-1m.txt\n");
		return 0;
	}
    const char *domain_file = argv[1];
    load_domains(domain_file);
    print_memory_usage();

    printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '%d'\n", queue);
	qh = nfq_create_queue(h, queue, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	printf("setting flags to request UID and GID\n");
	if (nfq_set_queue_flags(qh, NFQA_CFG_F_UID_GID, NFQA_CFG_F_UID_GID)) {
		fprintf(stderr, "This kernel version does not allow to "
				"retrieve process UID/GID.\n");
	}

	printf("setting flags to request security context\n");
	if (nfq_set_queue_flags(qh, NFQA_CFG_F_SECCTX, NFQA_CFG_F_SECCTX)) {
		fprintf(stderr, "This kernel version does not allow to "
				"retrieve security context.\n");
	}

	printf("Waiting for packets...\n");

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. Please, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}

