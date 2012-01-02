program test_libipq;

{
 Before running the program (as root/superuser) make sure to do the following if requierd:
 # modprobe iptable_filter
 # modprobe ip_queue

 # iptables -A OUTPUT -p icmp -j QUEUE

 Or any other protocol to queue ...

 The following code is a translation from the C code at man libipq
}

{$mode objfpc}{$H+}

uses
  Classes, libipq
  { you can add units after this };



begin
end.

