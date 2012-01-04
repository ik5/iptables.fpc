{ Binding of libnetfilter_queue/libnetfilter_queue.h

  Copyright (C) 2012 Ido Kanner idokan at@at gmail dot.dot com

  This library is free software; you can redistribute it and/or modify it
  under the terms of the GNU Library General Public License as published by
  the Free Software Foundation; either version 2 of the License, or (at your
  option) any later version.

  This program is distributed in the hope that it will be useful, but WITHOUT
  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
  FITNESS FOR A PARTICULAR PURPOSE. See the GNU Library General Public License
  for more details.

  You should have received a copy of the GNU Library General Public License
  along with this library; if not, write to the Free Software Foundation,
  Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
}

{$IFNDEF LINUX}
  {$ERROR This unit is binded to the Linux Operating system.}
{$ENDIF}
unit libnetfilter_queue;

{$mode fpc}{$packrecords c}

interface

uses
  ctypes, sockets;

const
  NETFILTER_QUEUE_LIB = 'libnetfilter_queue';

type
  pnfq_handle = ^nfq_handle;
  nfq_handle  = record end;

  pnfq_q_handle = ^nfq_q_handle;
  nfq_q_handle  = record end;

  pnfq_data = ^nfq_data;
  nfq_data  = record end;

var
  nfq_errno : cint; external NETFILTER_QUEUE_LIB;



implementation

end.

