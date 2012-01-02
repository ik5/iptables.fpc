
int identify_ip_protocol (ipq_packet_msg_t *msg)
{ 
  int protocol=0; /* 6 = TCP, 16 = UDP */

  /* Cast the IP Header from the raw packet */
  struct iphdr *iph = ((struct iphdr *) msg->payload);

  /* get the protocol identifier from the ip header */
  protocol = iph->protocol;

  return(protocol);

}

