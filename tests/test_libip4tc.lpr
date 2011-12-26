program test_libip4tc;

{$mode objfpc}{$H+}

uses
  BaseUnix, SysUtils, Classes, lipip4tc
  { you can add units after this };

type

  { TRules }

  TRules = class
  private
    FHandle : piptc_handle;
  public
    procedure OpenSnaphot;
    procedure CloseSnapshot;
    procedure ReopenSnapshot;

    constructor Create;
    destructor Destroy; override;
  end;

{ TRules }

procedure TRules.OpenSnaphot;
begin
  FHandle := iptc_init('filter');
  if not Assigned(FHandle) then
    begin
      raise Exception.CreateFmt('Error initializing: %s', [iptc_strerror(errno)]);
    end;
end;

procedure TRules.CloseSnapshot;
begin
  if Assigned(FHandle) then
    begin
      iptc_free(FHandle);
    end;
end;

procedure TRules.ReopenSnapshot;
begin
  CloseSnapshot;
  OpenSnaphot;
end;

constructor TRules.Create;
begin
  OpenSnaphot;
end;

destructor TRules.Destroy;
begin
  CloseSnapshot;
  inherited Destroy;
end;

var
  Rules : TRules;

begin
  Rules := TRules.Create;
  Rules.Free;
end.

