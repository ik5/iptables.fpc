program test_libipq;

{
 Before running the program (as root/superuser) make sure to do the following if requierd:
 # modprobe iptable_filter
 # modprobe ip_queue

 # iptables -A OUTPUT -p icmp -j QUEUE

 Or any other protocol to queue ...

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

begin
 h := ipq_create_handle(0, NFPROTO_IPV4);
 if h = nil then die(h);

 status := ipq_set_mode(h, IPQ_COPY_PACKET, BUFSIZE);
 if status < 0 then die(h);

 repeat
   status := ipq_read(h, buf, BUFSIZE, 0);
   if status < 0 then die(h);

   message_type := ipq_message_type(buf);
   //case message_type of

   //end;
 until true;
end.

