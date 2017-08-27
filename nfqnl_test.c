#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <libnet.h>
#include <arpa/inet.h>
#include <errno.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#define MAX_NUM 100
#define MAX_LEN 30 

unsigned char *packet;
int len;

/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi; 
	//int ret;
	//unsigned char *data;

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

	len = nfq_get_payload(tb, &packet);
	if (len >= 0)
		printf("payload_len=%d ", len);

	fputc('\n', stdout);

	return id;
}



int BSearch(char(*buf)[MAX_LEN], char *search_str, int len)
{
	int first = 0;
	int last = len - 1;
	int mid = 0;
	int length = strlen(search_str);

	while (first <= last)
	{
		mid = (first + last) / 2;
		if (memcmp(buf[mid], search_str, length) == 0)
		{
			return mid;
		}
		else
		{
			if (memcmp(buf[mid], search_str, length) > 0)
				last = mid - 1;
			else
				first = mid + 1;
		}
	}
	return -1;
}

int HostCheck(char *hostName)
{
	FILE *fp;
	char name[MAX_NUM][MAX_LEN];
	char tmp[MAX_LEN];
	int cnt = 0;

	fp = fopen("./weblist.txt","r");

	while((fgets(name[cnt],MAX_LEN,fp)) != NULL)
	{
		cnt++;
	}

	/* sorting the file data */

	for(int i=0; i < cnt - 1; i++)
	{
		for(int j=0; j < cnt-1-i; j++)
		{
			if(strcmp(name[j], name[j+1]) > 0)
			{
				strcpy(tmp, name[j]);
				strcpy(name[j], name[j+1]);
				strcpy(name[j+1], tmp);
			}
		}
	}

	return BSearch(name, hostName, cnt);
}

char *memstr(char *srcdata, char *find, int srclen)
{
	char *p;
	int findlen = strlen(find);
	for (p = srcdata; p <= (srcdata + srclen - findlen); p++)
	{
		if (memcmp(p, find, findlen) == 0)
			return p;
	}
	return NULL;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
		struct nfq_data *nfa, void *data)
{
	struct libnet_ipv4_hdr *iphdr;
	struct libnet_tcp_hdr *tcphdr;
	unsigned short ip_proto;
	char find_string1[] = "Host";
	char find_string2[] = "\r\n";
	char host_string[MAX_LEN];
	unsigned char *begin_addr;
	unsigned char *finish_addr; 
	while(1)
	{	
		u_int32_t id = print_pkt(nfa);
		printf("entering callback\n");

		int length = len;

		iphdr = (struct libnet_ipv4_hdr *)(packet);
		ip_proto = iphdr->ip_p;

		if(ip_proto == IPPROTO_TCP)
		{
			packet += iphdr->ip_hl * 4; 
			tcphdr = (struct libnet_tcp_hdr *)(packet); 
			packet += tcphdr->th_off * 4;				// pointer to Data
			length = length - iphdr->ip_hl*4 - tcphdr->th_off*4; 	// data length

			begin_addr = memstr(packet, find_string1, length);

			if(begin_addr == NULL)
				return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

			else
			{
				memset(host_string, 0, 30);
				begin_addr += 6;  
				finish_addr = memstr(begin_addr, find_string2, length - (begin_addr - packet));
				memcpy(host_string, begin_addr, (finish_addr - begin_addr));	
				printf("host : %s\n", host_string);
			}


			if(HostCheck(host_string) == -1) 
				return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
			else
				return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);

		}

		else
			return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
	}
}

int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
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
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

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
