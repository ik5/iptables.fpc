{

 Note: Require Root priviliges in order to execute the code !
}
program test_libip4tc;

{$mode fpc}{$H+}

uses
  BaseUnix, SysUtils, Classes, libip4tc
  { you can add units after this };

var
  handle : piptc_handle;
  chain  : PChar;

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

