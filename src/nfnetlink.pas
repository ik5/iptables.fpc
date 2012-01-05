{ Binding of linux/netfileter/nfnetlink.h

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
unit nfnetlink;

{$mode fpc}{$PACKRECORDS c}

interface

uses
  ctypes;

type
 nfnetlink_groups = cint;

const
  NFNLGRP_NONE                  = 0;
  NFNLGRP_CONNTRACK_NEW         = 1;
  NFNLGRP_CONNTRACK_UPDATE      = 2;
  NFNLGRP_CONNTRACK_DESTROY     = 3;
  NFNLGRP_CONNTRACK_EXP_NEW     = 4;
  NFNLGRP_CONNTRACK_EXP_UPDATE  = 5;
  NFNLGRP_CONNTRACK_EXP_DESTROY = 6;
  __NFNLGRP_MAX                 = 7;
  NFNLGRP_MAX                   = __NFNLGRP_MAX -1;

type
  pnfgenmsg = ^nfgenmsg;
 //General form of address family dependent message.
 nfgenmsg = record
   nfgen_family : cuint8;  // AF_xxx
   version      : cuint8;  // nfnetlink version
   res_id       : cuint16; // resource id
 end;

const
 NFNETLINK_V0 = 0;

(* netfilter netlink message types are split in two pieces:
 * 8 bit subsystem, 8bit operation.
 *)

function NFNL_SUBSYS_ID(x : cuint8) : cuint8; inline; cdecl;
function NFNL_MSG_TYPE(x : cuint8) : cuint8; inline; cdecl;

(* No enum here, otherwise __stringify() trick of MODULE_ALIAS_NFNL_SUBSYS()
 * won't work anymore *)
const
 NFNL_SUBSYS_NONE          = 0;
 NFNL_SUBSYS_CTNETLINK     = 1;
 NFNL_SUBSYS_CTNETLINK_EXP = 2;
 NFNL_SUBSYS_QUEUE         = 3;
 NFNL_SUBSYS_ULOG          = 4;
 NFNL_SUBSYS_COUNT         = 5;

(*
#ifdef __KERNEL__

#include <linux/netlink.h>
#include <linux/capability.h>
#include <net/netlink.h>

struct nfnl_callback
{
	int ( *call)(struct sock *nl, struct sk_buff *skb,
		struct nlmsghdr *nlh, struct nlattr *cda[]);
	const struct nla_policy *policy;	/* netlink attribute policy */
	const u_int16_t attr_count;		/* number of nlattr's */
};

struct nfnetlink_subsystem
{
	const char *name;
	__u8 subsys_id;			/* nfnetlink subsystem ID */
	__u8 cb_count;			/* number of callbacks */
	const struct nfnl_callback *cb;	/* callback for individual types */
};

extern int nfnetlink_subsys_register(const struct nfnetlink_subsystem *n);
extern int nfnetlink_subsys_unregister(const struct nfnetlink_subsystem *n);

extern int nfnetlink_has_listeners(unsigned int group);
extern int nfnetlink_send(struct sk_buff *skb, u32 pid, unsigned group,
			  int echo);
extern int nfnetlink_unicast(struct sk_buff *skb, u_int32_t pid, int flags);

#define MODULE_ALIAS_NFNL_SUBSYS(subsys) \
	MODULE_ALIAS("nfnetlink-subsys-" __stringify(subsys))

*)

implementation

function NFNL_SUBSYS_ID(x: cuint8): cuint8; cdecl;
begin
//#define NFNL_SUBSYS_ID(x)	((x & 0xff00) >> 8)
  NFNL_SUBSYS_ID := (x and $ff00) shr 8;
end;

function NFNL_MSG_TYPE(x: cuint8): cuint8; cdecl;
begin
// #define NFNL_MSG_TYPE(x)	(x & 0x00ff)
  NFNL_MSG_TYPE := x and $00ff;
end;

end.

