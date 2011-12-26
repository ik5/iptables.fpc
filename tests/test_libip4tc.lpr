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


begin
  handle := iptc_init('filter');
  if handle = nil then
    begin
      writeln(StdErr, 'Error initializing: ', iptc_strerror(errno));
      Exit;
    end;
end.

