program test_libnetfilter;

// iptables -A INPUT -p tcp --sport 80 -j NFQUEUE --queue-num 0

{$mode objfpc}{$H+}

uses
 libnetfilter_queue, netfilter, libnfnetlink, nfnetlink, netlink_kernel,
 linux_nfnetlink_queue, ctypes, Sockets, sysutils, BaseUnix
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
     write(format('hw_protocol=0x%.4x hook=%u id=%u ',
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
        write(format('%.2x:', [hwph^.hw_addr[i]]));
        inc(i);
      end;
     write(format('%.2x:', [hwph^.hw_addr[i-1]]));
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

function cb(gh   : pnfq_q_handle; nfmsg : nfgenmsg;
            nfad : pnfq_data;     data  : pointer) : cint; cdecl;
var
  id : cuint32;
begin
  id := print_pkt(nfad);
  writeln('Entering callback');
  Result := nfq_set_verdict(gh, id, NF_ACCEPT, 0, Nil);
end;

var
  h   : pnfq_handle;
  qh  : pnfq_q_handle;
  //nh  : pnfnl_handle;
  fd  : cint;
  rv  : cint;
  buf : array[0..4096] of char;

procedure die(const s : string); inline;
begin
  writeln(stderr, s);
  halt(1);
end;

begin
  if FpGetuid <> 0 then
   die('This program must be executed as root');

  writeln('opening library handle');
  h := nfq_open;
  if not Assigned(h) then
     die('Error during nfq_open()');

  writeln('unbinding existing nf_queue handler for AF_INET (if any)');
  if nfq_unbind_pf(h, AF_INET) < 0 then
   die('error during nfq_unbind_pf()');

  writeln('binding nfnetlink_queue as nf_queue handler for AF_INET');
  if nfq_bind_pf(h, AF_INET) < 0 then
   die('error during nfq_bind_pf()');

  writeln('binding this socket to queue "0"');
  qh := nfq_create_queue(h, 0, @cb, nil);
  if not Assigned(qh) then
   die('error during nfq_create_queue()');

  writeln('setting copy_packet mode');
  if nfq_set_mode(qh, NFQNL_COPY_PACKET, $ffff) < 0 then
   die('can''t set packet_copy mode');

  fd := nfq_fd(h);

  rv := fprecv(fd, @buf, Length(buf), 0);
  while (rv >= 0) do
   begin
     writeln('pkt received');
     nfq_handle_packet(h, @buf, rv);
     rv := fprecv(fd, @buf, Length(buf), 0);
   end;

  writeln('unbinding from queue 0');
  nfq_destroy_queue(qh);

  {$IFDEF INSANE}
  (* normally, applications SHOULD NOT issue this command, since
   * it detaches other programs/sockets from AF_INET, too ! *)
   writeln('unbinding from AF_INET');
  nfq_unbind_pf(h, AF_INET);
  {$ENDIF}

  writeln('closing library handle');
  nfq_close(h);
end.

