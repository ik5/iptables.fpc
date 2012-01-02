{ translation of linux/netlink.h

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
unit netlink;

{$mode fpc}{$packrecords c}

interface

uses
  ctypes, Sockets;

const
 NETLINK_ROUTE          = 0;	// Routing/device hook
 NETLINK_UNUSED         = 1;	// Unused number
 NETLINK_USERSOCK       = 2;  // Reserved for user mode socket protocols
 NETLINK_FIREWALL       = 3;	// Firewalling hook
 NETLINK_INET_DIAG      = 4;	// INET socket monitoring
 NETLINK_NFLOG          = 5;	// netfilter/iptables ULOG
 NETLINK_XFRM           = 6;  // ipsec
 NETLINK_SELINUX        = 7;	// SELinux event notifications
 NETLINK_ISCSI          = 8;  // Open-iSCSI
 NETLINK_AUDIT          = 9;  // auditing
 NETLINK_FIB_LOOKUP     = 10;
 NETLINK_CONNECTOR      = 11;
 NETLINK_NETFILTER      = 12; // netfilter subsystem
 NETLINK_IP6_FW         = 13;
 NETLINK_DNRTMSG        = 14; // DECnet routing messages
 NETLINK_KOBJECT_UEVENT = 15; // Kernel messages to userspace
 NETLINK_GENERIC        = 16;
// leave room for NETLINK_DM (DM Events)
 NETLINK_SCSITRANSPORT  = 18; // SCSI Transports
 NETLINK_ECRYPTFS       = 19;
 NETLINK_RDMA           = 20;

 MAX_LINKS              = 32;

type
 {$IF not defined(__kernel_sa_family_t)}
 __kernel_sa_family_t = cushort;
 {$ENDIF}
 psockaddr_nl = ^sockaddr_nl;
 sockaddr_nl  = record
   nl_family : __kernel_sa_family_t; // AF_NETLINK
   nl_pad    : cuint32;              // zero
   nl_pid    : cuint32;              // port ID
   nl_groups : cuint32;              // multicast groups mask
 end;

 pnlmsghdr = ^nlmsghdr;
 nlmsghdr  = record
  nlmsg_len   : cuint32; // Length of message including header
  nlmsg_type  : cuint16; // Message content
  nlmsg_flags : cuint16; // Additional flags
  nlmsg_seq   : cuint32; // Sequence number
  nlmsg_pid   : cuint32; // Sending process port ID
 end;

// Flags values
const
 NLM_F_REQUEST   = 1;  // It is request message.
 NLM_F_MULTI     = 2;  // Multipart message, terminated by NLMSG_DONE
 NLM_F_ACK       = 4;  // Reply with ack, with zero or error code
 NLM_F_ECHO      = 8;  // Echo this request
 NLM_F_DUMP_INTR = 16; // Dump was inconsistent due to sequence change

 // Modifiers to GET request
 NLM_F_ROOT   = $100; // specify tree	root
 NLM_F_MATCH  = $200; // return all matching
 NLM_F_ATOMIC = $400; // atomic GET
 NLM_F_DUMP   = NLM_F_ROOT or NLM_F_MATCH;

 // Modifiers to NEW request
 NLM_F_REPLACE = $100; // Override existing
 NLM_F_EXCL    = $200; // Do not touch, if it exists
 NLM_F_CREATE  = $400; // Create, if it does not exist
 NLM_F_APPEND  = $800; // Add to end of list

(*
   4.4BSD ADD		NLM_F_CREATE|NLM_F_EXCL
   4.4BSD CHANGE	NLM_F_REPLACE

   True CHANGE		NLM_F_CREATE|NLM_F_REPLACE
   Append		NLM_F_CREATE
   Check		NLM_F_EXCL
 *)

 NLMSG_ALIGNTO = cuint(4);

function NLMSG_ALIGN(len : cint) : cint; inline; cdecl;
function NLMSG_HDRLEN : cint; inline; cdecl;
function NLMSG_LENGTH(len : cint) : cint; inline; cdecl;
function NLMSG_SPACE(len : cint) : cint; inline; cdecl;
function NLMSG_DATA(nlh : cint) : pointer; inline; cdecl;

(*
#define NLMSG_NEXT(nlh,len)	 ((len) -= NLMSG_ALIGN((nlh)->nlmsg_len), \
				  (struct nlmsghdr* )(((char* )(nlh)) + NLMSG_ALIGN((nlh)->nlmsg_len)))
#define NLMSG_OK(nlh,len) ((len) >= (int)sizeof(struct nlmsghdr) && \
			   (nlh)->nlmsg_len >= sizeof(struct nlmsghdr) && \
			   (nlh)->nlmsg_len <= (len))
*)
function NLMSG_PAYLOAD(nlh : nlmsghdr; len : cint) : cint; inline; cdecl;

const
 NLMSG_NOOP    = $1; // Nothing
 NLMSG_ERROR   = $2; // Error
 NLMSG_DONE    = $3; // End of a dump
 NLMSG_OVERRUN = $4; // Data lost

 NLMSG_MIN_TYPE = $10; // < 0x10: reserved control messages

type
 pnlmsgerr = ^nlmsgerr;
 nlmsgerr  = record
  error : cint;
  msg   : nlmsghdr;
 end;

const
 NETLINK_ADD_MEMBERSHIP  = 1;
 NETLINK_DROP_MEMBERSHIP = 2;
 NETLINK_PKTINFO         = 3;
 NETLINK_BROADCAST_ERROR = 4;
 NETLINK_NO_ENOBUFS      = 5;

type
  pnl_pktinfo = ^nl_pktinfo;
  nl_pktinfo  = record
    group : cuint32;
  end;

const
  NET_MAJOR = 36; // Major 36 is reserved for networking

  NETLINK_UNCONNECTED = 0;
  NETLINK_CONNECTED   = 1;

(*
 *  <------- NLA_HDRLEN ------> <-- NLA_ALIGN(payload)-->
 * +---------------------+- - -+- - - - - - - - - -+- - -+
 * |        Header       | Pad |     Payload       | Pad |
 * |   (struct nlattr)   | ing |                   | ing |
 * +---------------------+- - -+- - - - - - - - - -+- - -+
 *  <-------------- nlattr->nla_len -------------->
 *)

type
 pnlattr = ^nlattr;
 nlattr  = record
   nla_len  : cuint16;
   nla_type : cuint16;
 end;

(*
 * nla_type (16 bits)
 * +---+---+-------------------------------+
 * | N | O | Attribute Type                |
 * +---+---+-------------------------------+
 * N := Carries nested attributes
 * O := Payload stored in network byte order
 *
 * Note: The N and O flag are mutually exclusive.
 *)
const
 NLA_F_NESTED        = 1 shl 15;
 NLA_F_NET_BYTEORDER = 1 shl 14;
 NLA_TYPE_MASK       = not (NLA_F_NESTED or NLA_F_NET_BYTEORDER);

 NLA_ALIGNTO         = 4;

function NLA_ALIGN(len : cint) : cint; inline; cdecl;
function NLA_HDRLEN : cint; inline; cdecl;

implementation

function NLMSG_ALIGN(len: cint): cint; cdecl;
begin
// #define NLMSG_ALIGN(len) ( ((len)+NLMSG_ALIGNTO-1) & ~(NLMSG_ALIGNTO-1) )
 NLMSG_ALIGN := (len + NLMSG_ALIGNTO -1) and not (NLMSG_ALIGNTO-1);
end;

function NLMSG_HDRLEN: cint; cdecl;
begin
// #define NLMSG_HDRLEN	 ((int) NLMSG_ALIGN(sizeof(struct nlmsghdr)))
 NLMSG_HDRLEN := NLMSG_ALIGN(sizeof(nlmsghdr));
end;

function NLMSG_LENGTH(len: cint): cint; cdecl;
begin
// #define NLMSG_LENGTH(len) ((len)+NLMSG_ALIGN(NLMSG_HDRLEN))
  NLMSG_LENGTH := len + NLMSG_ALIGN(NLMSG_HDRLEN);
end;

function NLMSG_SPACE(len: cint): cint; cdecl;
begin
// #define NLMSG_SPACE(len) NLMSG_ALIGN(NLMSG_LENGTH(len))
  NLMSG_SPACE := NLMSG_ALIGN(NLMSG_LENGTH(len));
end;

function NLMSG_DATA(nlh: cint): pointer; cdecl;
begin
// #define NLMSG_DATA(nlh)  ((void* )(((char* )nlh) + NLMSG_LENGTH(0)))
  NLMSG_DATA := Pointer((pchar(nlh))+(NLMSG_LENGTH(0)));
end;

function NLMSG_PAYLOAD(nlh: nlmsghdr; len: cint): cint; cdecl;
begin
// #define NLMSG_PAYLOAD(nlh,len) ((nlh)->nlmsg_len - NLMSG_SPACE((len)))
  NLMSG_PAYLOAD := nlh.nlmsg_len - NLMSG_SPACE(len);
end;

function NLA_ALIGN(len: cint): cint; cdecl;
begin
//#define NLA_ALIGN(len)		(((len) + NLA_ALIGNTO - 1) & ~(NLA_ALIGNTO - 1))
 NLA_ALIGN := (len + NLA_ALIGNTO -1) and not (NLA_ALIGNTO -1);
end;

function NLA_HDRLEN: cint; cdecl;
begin
//#define NLA_HDRLEN		((int) NLA_ALIGN(sizeof(struct nlattr)))
 NLA_HDRLEN := NLA_ALIGN(sizeof(nlattr));
end;


end.

