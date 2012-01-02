{

 Note: Require Root priviliges in order to execute the code !
}
program test_libip4tc;

{$mode fpc}{$H+}

uses
  BaseUnix, SysUtils, strutils, libip4tc, libxtables, x_tables, sockets
  { you can add units after this };

const
  invchar : array[Boolean] of string = ('', '!');

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
  write(invchar[invert]);

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
var
  i : Cardinal;
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

function print_match(e : pxt_entry_match; ip : pipt_ip) : Boolean;
var
  match   : pxtables_match;
  //matches : ppxtables_rule_match;
begin
  match := xtables_find_match(e^.u.user.name, XTF_TRY_LOAD, nil);
  if match = nil then
    begin
      writeln(stderr, 'Can''t find library for match ', e^.u.user.name);
      Exit(false);
    end;
  write('-m ', e^.u.user.name);

  if match^.save <> nil then
    match^.save(ip, e);

 print_match := True;
end;

// print a given ip including mask if neccessary
procedure print_ip(prefix : PChar; ip, mask : cuint32; invert : ByteBool);
begin
  if (mask = 0) and (ip = 0) then exit;
  write(prefix, ' ', invchar[invert],
  printf("%s %s%u.%u.%u.%u",
    prefix,
    invert ? "! " : "",
    IP_PARTS(ip));

  if (mask != 0xffffffff)
    printf("/%u.%u.%u.%u ", IP_PARTS(mask));
  else
    printf(" ");
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

