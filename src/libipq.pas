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
{$END}

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

(*
ipq_packet_msg_t *ipq_get_packet(const unsigned char *buf);

int ipq_message_type(const unsigned char *buf);

int ipq_get_msgerr(const unsigned char *buf);

int ipq_set_verdict(const struct ipq_handle *h,
                    ipq_id_t id,
                    unsigned int verdict,
                    size_t data_len,
                    unsigned char *buf);

int ipq_ctl(const struct ipq_handle *h, int request, ...);

char *ipq_errstr(void);
void ipq_perror(const char *s);
*)

implementation

end.

