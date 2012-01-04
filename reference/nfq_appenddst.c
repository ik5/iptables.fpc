#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

static uint32_t checksum(void *buffer, unsigned int count, uint32_t startsum)
{
uint16_t *up = (uint16_t *)buffer;
  uint32_t sum = startsum;
  uint32_t upper16;

  for (;count > 1; count -= 2)
    sum += *up++;

  if (count > 0)
    sum += (uint16_t) *(uint8_t *)up;

  while ((upper16 = (sum >> 16)) != 0)
    sum = (sum & 0xffff) + upper16;

  return sum;
}

uint16_t udp_sum(struct iphdr *iph, struct udphdr *udph) {
  udph->check = 0;

  uint32_t sum;
  uint16_t nproto;

  sum = checksum(&iph->saddr, sizeof(iph->saddr) + sizeof(iph->daddr), 0);
  nproto = htons(IPPROTO_UDP);
  sum = checksum(&nproto, sizeof(nproto), sum);
  sum = checksum(&udph->len, sizeof(udph->len), sum);
  sum = checksum(udph, sizeof(struct udphdr) + ntohs(udph->len), sum);

  return ~sum;
}

int append_dst(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfad, void *nodata) {
  int id, ret, data_len;
  char *payload = NULL, *data;
  struct iphdr *iph;
  struct udphdr *udph;
  char buf[0xffff];

  if ((ret = nfq_get_payload(nfad, &payload)) >= 0 && payload) {
    memcpy(buf, payload, ret);
    iph = (struct iphdr *)buf;
    udph = (struct udphdr *)((void *)iph + (iph->ihl*4));
    data = (char *)((void *)udph + sizeof(struct udphdr));
    data_len = ntohs(udph->len) - sizeof(struct udphdr);

    memcpy(&data[data_len], &iph->daddr, 4);
    memcpy(&data[data_len+4], &udph->dest, 2);

    data_len += 6;

    iph->tot_len = htons(ntohs(iph->tot_len) + 6);
    udph->len = htons(ntohs(udph->len) + 6);

    iph->check = 0;
    iph->check = ~checksum(iph, sizeof(struct iphdr), 0);
    udph->check = udp_sum(iph, udph);

    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfad);
    if (ph) {
      id = ntohl(ph->packet_id);
      int rv = nfq_set_verdict(qh, id, NF_ACCEPT, ntohs(iph->tot_len), buf);
    } else {
      printf("couldn't get packet ID!\n");
    }
  }

  return 0;
}

int main() {
  struct nfq_handle *h;
  struct nfq_q_handle *qh;

  h = nfq_open();
  if (!h) { perror("nfq_open"); exit(1); }

  if (nfq_unbind_pf(h, PF_INET) < 0) {
    perror("nfq_unbind_pf");
    exit(1);
  }

  if (nfq_bind_pf(h, PF_INET) < 0) {
    perror("nfq_bind_pf");
    exit(1);
  }

  qh = nfq_create_queue(h, 0, &append_dst, NULL);
  if (!qh) { perror("nfq_create_queue"); exit(1); }

  if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
    perror("nfq_set_mode");
    exit(1);
  }

  int rv, fd;
  char buf[0xffff];

  fd = nfq_fd(h);

  while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
    printf(".");fflush(stdout);
    nfq_handle_packet(h, buf, rv);
  }

  return 0;
}
