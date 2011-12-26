unit fpipv4tables;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils;

type
  TChain = class(TCollectionItem)

  end;

  { TChains }

  TChains = class(TCollection)
  public
    //constructor Create(AItemClass : TCollectionItem); override;
  end;

  { TIPTables }

  TIPTables = class
  private
    FHandle : piptc_handle;
  public
    procedure OpenSnaphot;
    procedure CloseSnapshot;
    procedure ReopenSnapshot;

    constructor Create;
    destructor Destroy; override;
  end;

implementation
uses BaseUnix, lipip4tc;

{ TChains }

//constructor TChains.Create(AItemClass: TCollectionItem);
//begin
//
//end;

{ TRules }

procedure TIPTables.OpenSnaphot;
begin
  FHandle := iptc_init('filter');
  if not Assigned(FHandle) then
    begin
      raise Exception.CreateFmt('Error initializing: %s', [iptc_strerror(errno)]);
    end;
end;

procedure TIPTables.CloseSnapshot;
begin
  if Assigned(FHandle) then
    begin
      iptc_free(FHandle);
    end;
end;

procedure TIPTables.ReopenSnapshot;
begin
  CloseSnapshot;
  OpenSnaphot;
end;

constructor TIPTables.Create;
begin
  OpenSnaphot;
end;

destructor TIPTables.Destroy;
begin
  CloseSnapshot;
  inherited Destroy;
end;

end.

