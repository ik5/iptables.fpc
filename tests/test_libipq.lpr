program test_libipq;

{
 Before running the program (as root/superuser) make sure to do the following if requierd:
 # modprobe iptable_filter
 # modprobe ip_queue

 # iptables -A OUTPUT -p icmp -j QUEUE

 Or any other protocol to queue ...

 To clear the rules:
  # iptables -F
  # iptables -X
  # iptables -t nat -F
  # iptables -t nat -X
  # iptables -t mangle -F
  # iptables -t mangle -X
  # iptables -P INPUT ACCEPT
  # iptables -P FORWARD ACCEPT
  # iptables -P OUTPUT ACCEPT

 The following code is a translation from the C code at man libipq
}

{$mode fpc}{$H+}

uses
  libipq, netfilter, ip_queue, ctypes, netlink
  { you can add units after this };

const
 BUFSIZE = 2048;

procedure die(h : pipq_handle);
begin
  ipq_perror('passer');
  ipq_destroy_handle(h);
  halt(1);
end;

var
 status       : cint;
 buf          : array[0..BUFSIZE-1] of char;
 h            : pipq_handle;
 message_type : cint;
 m            : pipq_packet_msg_t;

begin
 h := ipq_create_handle(0, NFPROTO_IPV4);
 if h = nil then die(h);

 status := ipq_set_mode(h, IPQ_COPY_PACKET, BUFSIZE);
 if status < 0 then die(h);

 repeat
   status := ipq_read(h, buf, BUFSIZE, 0);
   if status < 0 then die(h);

   message_type := ipq_message_type(buf);
   case message_type of
     NLMSG_ERROR : writeln(stderr, 'Received error message ',
                           ipq_get_msgerr(buf));
     IPQM_PACKET : begin
                    writeln('IPQM_PACKET');
                    m      := ipq_get_packet(buf);
                    status := ipq_set_verdict(h, m^.packet_id, NF_ACCEPT, 0, Nil);
                    if (status < 0) then die(h);

                   end;
     else
       writeln(stderr, 'Unknown message type!');
   end;
 until true;
                    n
 ipq_destroy_handle(h);
end.

