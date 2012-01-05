program test_libnetfilter;

{$mode objfpc}{$H+}

uses
 libnetfilter_queue, netfilter, libnfnetlink, nfnetlink, netlink_kernel,
 linux_nfnetlink_queue, ctypes, Sockets, sysutils
  { you can add units after this };

// Implementing http://www.netfilter.org/projects/libnetfilter_queue/doxygen/nfqnl__test_8c_source.html
// In Pascal

// returns packet id
function print_pkt(tb : pnfq_data) : cuint32;
var
  id    : cint;
  ph    : pnfqnl_msg_packet_hdr;
  hwph  : pnfqnl_msg_packet_hw;
  mark,
  ifi   : cuint32;
  ret   : cint;
  data  : PChar;
  i,
  hlen  : cint;
begin
  id := 0;
  ph := nfq_get_msg_packet_hdr(tb);
  if Assigned(ph) then
   begin
     id := ntohl(ph^.packet_id);
     write(format('hw_protocol=0x%04x hook=%u id=%u ',
                  [ntohs(ph^.hw_protocol), ph^.hook, id]));
   end;

  hwph := nfq_get_packet_hw(tb);
  if Assigned(hwph) then
   begin
     hlen := NToHs(hwph^.hw_addrlen);
     write('gw_src_addr=');
     i := 0;
     while i < hlen -1 do
      begin
        write(format('%02x:', [hwph^.hw_addr[i]]));
        inc(i);
      end;
     write(format('%02x:', [hwph^.hw_addr[i-1]]));
   end;

  mark := nfq_get_nfmark(tb);
  if mark > 0 then write('mark=', mark, ' ');

  ifi := nfq_get_indev(tb);
  if ifi > 0 then write('indev=', ifi, ' ');

  ifi := nfq_get_outdev(tb);
  if ifi > 0 then write('outdev=', ifi > 0, ' ');

  ifi := nfq_get_physindev(tb);
  if ifi > 0 then write('physindev=', ifi > 0, ' ');

  ifi := nfq_get_physoutdev(tb);
  if ifi > 0 then write('physoutdev=', ifi > 0);

  ret := nfq_get_payload(tb, @data);
  if ret >= 0 then write('payload_len=', ret, ' ');
  writeln;

  Result := id;
end;

(*

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data)
{
        u_int32_t id = print_pkt(nfa);
        printf("entering callback\n");
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
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

        while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
                printf("pkt received\n");
                nfq_handle_packet(h, buf, rv);
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
*)

begin
end.

