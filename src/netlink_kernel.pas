{ Binding of /netlink/netlink-kernel.h

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
unit netlink_kernel;

{$mode fpc}{$PACKRECORDS c}

interface

uses
  ctypes, sockets;

type
  psockaddr_nl = ^sockaddr_nl;
  (**
   * Netlink socket address
   * @ingroup nl
   *)
  sockaddr_nl  = record
    nl_family : sa_family_t; // socket family (AF_NETLINK)
    nl_pad    : cushort;     // Padding (unused)
    nl_pid    : cuint32;     // Unique process ID
    nl_groups : cuint32;     // Multicast group subscriptions
  end;

  pnlmsghdr = ^nlmsghdr;
  (* Netlink message header
   * @ingroup msg
   *)
  nlmsghdr  = record
    nlmsg_len   : cuint32; // Length of message including header.
    nlmsg_type  : cuint16; // Message type (content type)
    nlmsg_flags : cuint16; // Message flags
    nlmsg_seq   : cuint32; // Sequence number
    nlmsg_pid   : cuint32; // Netlink PID of the proccess sending the message.
  end;

  // @name Standard message flags
const
(**
 * Must be set on all request messages (typically from user space to
 * kernel space).
 * @ingroup msg
 *)
 NLM_F_REQUEST = 1;
 (**
  * Indicates the message is part of a multipart message terminated
  * by NLMSG_DONE.
  *)
 NLM_F_MULTI   = 2;
 (**
  * Request for an acknowledgment on success.
  *)
 NLM_F_ACK     = 4;
 (**
  * Echo this request
  *)
 NLM_F_ECHO    = 8;

 // @name Additional message flags for GET requests
 (**
  * Return the complete table instead of a single entry.
  * @ingroup msg
  *)
 NLM_F_ROOT   = $100;
 (**
  * Return all entries matching criteria passed in message content.
  *)
 NLM_F_MATCH  = $200;
 (**
  * Return an atomic snapshot of the table being referenced. This
  * may require special privileges because it has the potential to
  * interrupt service in the FE for a longer time.
  *)
 NLM_F_ATOMIC = $400;
 (**
  * Dump all entries
  *)
 NLM_F_DUMP   = NLM_F_ROOT or NLM_F_MATCH;

 // @name Additional messsage flags for NEW requests

 (**
  * Replace existing matching config object with this request.
  * @ingroup msg
  *)
 NLM_F_REPLACE = $100;
 (**
  * Don't replace the config object if it already exists.
  *)
 NLM_F_EXCL    = $200;
 (**
  * Create config object if it doesn't already exist.
  *)
 NLM_F_CREATE  = $400;
 (**
  * Add to the end of the object list.
  *)
 NLM_F_APPEND  = $800;

 // @name Standard Message types
 (**
  * No operation, message must be ignored
  * @ingroup msg
  *)
 NLMSG_NOOP     = $1;
 (**
  * The message signals an error and the payload contains a nlmsgerr
  * structure. This can be looked at as a NACK and typically it is
  * from FEC to CPC.
  *)
 NLMSG_ERROR    = $2;
 (**
  * Message terminates a multipart message.
  *)
 NLMSG_DONE     = $3;
 (**
  * The message signals that data got lost
  *)
 NLMSG_OVERRUN  = $4;
 (**
  * Lower limit of reserved message types
  *)
 NLMSG_MIN_TYPE = $10;

type
  pnlmsgerr = ^nlmsgerr;
 (*
  * Netlink error message
  * @ingroup msg
  *)
  nlmsgerr = record
    error : cint;     // Error code (errno number)
    msg   : nlmsghdr; // Original netlink message causing the error
  end;

  pnl_pktinfo = ^nl_pktinfo;
  nl_pktinfo  = record
    group : cuint32;
  end;

implementation

end.

