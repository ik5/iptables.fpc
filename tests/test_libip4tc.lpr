{

 Note: Require Root priviliges in order to execute the code !
}
program test_libip4tc;

{$mode fpc}{$H+}

uses
  BaseUnix, SysUtils, libip4tc, sockets
  { you can add units after this };

type
 (**
 * struct xtables_pprot -
 *
 * A few hardcoded protocols for 'all' and in case the user has no
 * /etc/protocols.
 *)
  Txtables_pprot = record
    name : PChar;
    num  : Byte;
  end;

var
  handle : piptc_handle;
  chain  : PChar;

procedure print_iface(letter : char; iface : PChar; mask : PChar; invert : ByteBool);
var
  i : longword;
begin
  if mask[0] = #0 then
    exit;

  write(letter, ' ');
  if invert then
    write('!');

  for i := 0 to IFNAMSIZ -1 do
   begin
    if mask[i] <> #0 then
      begin
        if iface[i] <> #0 then
          write(iface[i]);
      end
    else begin
          if iface[i-1] <> #0 then
            write('+');
          break;
         end;
   end;

  write(' ');
end;



begin
  handle := iptc_init('filter');
  if handle = nil then
    begin
      writeln(StdErr, 'Error initializing: ', iptc_strerror(errno));
      Exit;
    end;

  chain := iptc_first_chain(handle);
  while (chain <> nil) do
    begin
      writeln(chain);
      chain := iptc_next_chain(handle);
    end;

  if handle <> nil then
    iptc_free(Handle);
end.

