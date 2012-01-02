{ translation of libipq.h

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
  {$ERROR This unit can work only with Linux - It requires iptables that are part of the Linux kernel}
{$ENDIF}
unit libipq;

{$mode fpc}{$packrecords c}

interface

uses
  ctypes;

const
  IPQ_LIB = 'libipq';

type
 pipq_id_t = ^ipq_id_t;
 ipq_id_t  = culong;

{$IF not defined(MSG_TRUNC)}
// FIXME: glibc sucks
const
 MSG_TRUNC = $20;
{$ENDIF}

{$IFNDEF USE_NETLINK}
type
 {$IF not defined(__kernel_sa_family_t)}
 __kernel_sa_family_t = cushort;
 {$ENDIF}
 psockaddr_nl = ^sockaddr_nl;
 sockaddr_nl  = record
   nl_family : __kernel_sa_family_t;
   nl_pid    : cuint32;
   nl_groups : cuint32;
 end;
{$ENDIF}

{$IF not defined(cssize_t)}
type
 cssize_t = clong;
{$ENDIF}

{$IFNDEF USE_IPQUEUE}
type
 pipq_packet_msg = ^ipq_packet_msg;
 ipq_packet_msg  = record
   packet_id      : culong;
   mark           : culong;
   timestamp_sec  : clong;
   timestamp_usec : clong;
   hook           : cuint;
   indev_name     : array[0..15] of char;
   outdev_name    : array[0..15] of char;
   hw_protocol    : cint16;
   hw_type        : cushort;
   hw_addrlen     : cuchar;
   hw_addr        : array[0..7] of char;
   data_len       : csize_t;
   payload        : array[0..0] of char;
 end;
 pipq_packet_msg_t = ^ipq_packet_msg_t;
 ipq_packet_msg_t  = ipq_packet_msg;
{$ENDIF}

type
 pipq_handle = ^ipq_handle;
 ipq_handle  = record
   fd       : cint;
   blocking : cuint8;
   local    : sockaddr_nl;
   peer     : sockaddr_nl;
 end;

function ipq_create_handle(flags : cuint32; protocol : cuint32) : pipq_handle;
 cdecl; external IPQ_LIB;

function ipq_destroy_handle(h : pipq_handle) : cint;
 cdecl; external IPQ_LIB;

function ipq_read(h       : pipq_handle;
                  buf     : PChar;
                  len     : csize_t;
                  timeout : cint)         :  cssize_t;
 cdecl; external IPQ_LIB;


function ipq_set_mode(h    : pipq_handle;
                      mode : cuint8;
                      len  : csize_t)     : cint;
 cdecl; external IPQ_LIB;


function ipq_get_packet(bug : PChar) : pipq_packet_msg_t;
 cdecl; external IPQ_LIB;

function ipq_message_type(bug : PChar) : cint;
 cdecl; external IPQ_LIB;

function ipq_get_msgerr(buf : PChar) : cint;
 cdecl; external IPQ_LIB;

function ipq_set_verdict(h        : pipq_handle;
                         id       : ipq_id_t;
                         verdict  : cuint;
                         data_len : csize_t;
                         buf      : PChar)        : cint;
 cdecl; external IPQ_LIB;

function ipq_ctl(h : pipq_handle; request : cint) : cint;
 cdecl; varargs; external IPQ_LIB;

function ipq_errstr : PChar;
 cdecl; external IPQ_LIB;

procedure ipq_perror(s : PChar);
  cdecl; external IPQ_LIB;

implementation

end.

