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

  Libipq
    provides an API for communicating with ip_queue.  The following is an
    overview of API usage, refer to individual man pages for more details
    on each function.
}
{$IFNDEF LINUX}
  {$ERROR This unit can work only with Linux - It requires iptables that are part of the Linux kernel}
{$ENDIF}
unit libipq;

{$mode fpc}{$packrecords c}

interface

uses
  ctypes, ip_queue, netlink;

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

{$IF not defined(cssize_t)}
type
 cssize_t = clong;
{$ENDIF}

type
 pipq_handle = ^ipq_handle;
 ipq_handle  = record
   fd       : cint;
   blocking : cuint8;
   local    : sockaddr_nl;
   peer     : sockaddr_nl;
 end;

// Initialise library, return context handle
function ipq_create_handle(flags : cuint32; protocol : cuint32) : pipq_handle;
 cdecl; external IPQ_LIB;

// Destroy context handle and associated resources.
function ipq_destroy_handle(h : pipq_handle) : cint;
 cdecl; external IPQ_LIB;

// Wait for a queue message to arrive from ip_queue and read it into a buffer.
function ipq_read(h       : pipq_handle;
                  buf     : PChar;
                  len     : csize_t;
                  timeout : cint)         :  cssize_t;
 cdecl; external IPQ_LIB;

(* Set the queue mode, to copy either packet metadata, or payloads as well as
   metadata to userspace.
*)
function ipq_set_mode(h    : pipq_handle;
                      mode : cuint8;
                      len  : csize_t)     : cint;
 cdecl; external IPQ_LIB;

// Retrieve a packet message from the buffer.
function ipq_get_packet(bug : PChar) : pipq_packet_msg_t;
 cdecl; external IPQ_LIB;

// Determine message type in the buffer.
function ipq_message_type(bug : PChar) : cint;
 cdecl; external IPQ_LIB;

// Retrieve an error message from the buffer.
function ipq_get_msgerr(buf : PChar) : cint;
 cdecl; external IPQ_LIB;

// Set a verdict on a packet, optionally replacing its contents.
function ipq_set_verdict(h        : pipq_handle;
                         id       : ipq_id_t;
                         verdict  : cuint;
                         data_len : csize_t;
                         buf      : PChar)        : cint;
 cdecl; external IPQ_LIB;

function ipq_ctl(h : pipq_handle; request : cint) : cint;
 cdecl; varargs; external IPQ_LIB;

// Return an error message corresponding to the internal ipq_errno variable.
function ipq_errstr : PChar;
 cdecl; external IPQ_LIB;

// Helper function to print error messages to stderr.
procedure ipq_perror(s : PChar);
  cdecl; external IPQ_LIB;

implementation

end.

