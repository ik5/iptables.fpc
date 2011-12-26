{

 Note: Require Root priviliges in order to execute the code !
}
program test_libip4tc;

{$mode fpc}{$H+}

uses
  BaseUnix, SysUtils, strutils, libip4tc, sockets
  { you can add units after this };

type
 (**
 * struct xtables_pprot -
 *
 * A few hardcoded protocols for 'all' and in case the user has no
 * /etc/protocols.
 *)
  Txtables_pprot = record
    name : String;
    num  : Byte;
  end;

  TProtos = array of Txtables_pprot;

var
  handle : piptc_handle;
  chain  : PChar;
  protos : TProtos;

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

// Quick and dirty and not very efficient /etc/protocols parser
procedure get_protos(var protos_arr : TProtos);
var
  f                      : TextFile;
  line,tmpl, proto, snum : AnsiString;
  i                      : integer;

begin
  Assign(f, '/etc/protocols');
  reset(f);
  SetLength(protos_arr, 0);
  FillChar(protos_arr, sizeof(Protos_arr), 0);
  while not EOF(f) do
   begin
     readln(f, line);
     tmpl := trim(line);
     if (tmpl = '') or (Copy(tmpl, 1,1) = '#') then
       continue;

     SetLength(protos_arr, Length(protos) +1);
     i := Pos(#32, tmpl);
     if i = 0 then i := Pos(#9, tmpl);

     proto := Copy(tmpl, 1, i-1);
     snum  := TrimLeft(Copy(tmpl, i, Length(tmpl) -i));
     i := Pos(#32, snum);
     if i = 0 then
       i := Pos(#9, snum);
     snum  := Copy(snum, 1, i-1);
     i := Length(protos);
     protos_arr[i-1].name := proto;
     protos_arr[i-1].num  := StrToInt(snum);
   end;
  Close(f);
end;

procedure print_proto(proto : byte; invert : ByteBool);
const
  invchar : array[Boolean] of string = ('', '!');
begin
  for i := low(protos) to high(protos) do
   begin
     if protos[i].num = proto then
       begin
         write('-p ', invchar[invert], protos[i].name);
         exit;
       end;
   end;

  write('-p ', invchar[invert], proto);
end;

begin
  get_protos(protos);
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

