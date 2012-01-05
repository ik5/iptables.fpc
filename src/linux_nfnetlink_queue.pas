{ Binding of libnetfilter_queue/linux_nfnetlink_queue.h

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
unit linux_nfnetlink_queue;

{$mode fpc}{$PACKRECORDS c}

interface

uses
  ctypes;

type
 nfqnl_msg_types = cint;

const
 NFQNL_MSG_PACKET  = 0; // packet from kernel to userspace
 NFQNL_MSG_VERDICT = 1; // verdict from userspace to kernel
 NFQNL_MSG_CONFIG  = 2; // connect to a particular queue
 NFQNL_MSG_MAX     = 3;

type
 pnfqnl_msg_packet_hdr = ^nfqnl_msg_packet_hdr;
 nfqnl_msg_packet_hdr  = packed record
   packet_id   : cuint32; // unique ID of packet in queue
   hw_protocol : cuint16; // hw protocol (network order)
   hook        : cuin8;   // netfilter hook
 end;

 pnfqnl_msg_packet_hw = ^nfqnl_msg_packet_hw;
 nfqnl_msg_packet_hw  = packed record
   hw_addrlen : cuint16;
   _pad       : cuint16;
   hw_addr    : array[0..7] of cuint8;
 end;

 pnfqnl_msg_packet_timestamp = ^nfqnl_msg_packet_timestamp;
 nfqnl_msg_packet_timestamp  = packed record
   sec, usec : cuint64;
 end;


(*
struct nfqnl_msg_packet_timestamp {
	aligned_u64	sec;
	aligned_u64	usec;
} __attribute__ ((packed));

enum nfqnl_attr_type {
	NFQA_UNSPEC,
	NFQA_PACKET_HDR,
	NFQA_VERDICT_HDR,		/* nfqnl_msg_verdict_hrd */
	NFQA_MARK,			/* u_int32_t nfmark */
	NFQA_TIMESTAMP,			/* nfqnl_msg_packet_timestamp */
	NFQA_IFINDEX_INDEV,		/* u_int32_t ifindex */
	NFQA_IFINDEX_OUTDEV,		/* u_int32_t ifindex */
	NFQA_IFINDEX_PHYSINDEV,		/* u_int32_t ifindex */
	NFQA_IFINDEX_PHYSOUTDEV,	/* u_int32_t ifindex */
	NFQA_HWADDR,			/* nfqnl_msg_packet_hw */
	NFQA_PAYLOAD,			/* opaque data payload */

	__NFQA_MAX
};
#define NFQA_MAX (__NFQA_MAX - 1)

struct nfqnl_msg_verdict_hdr {
	u_int32_t verdict;
	u_int32_t id;
} __attribute__ ((packed));


enum nfqnl_msg_config_cmds {
	NFQNL_CFG_CMD_NONE,
	NFQNL_CFG_CMD_BIND,
	NFQNL_CFG_CMD_UNBIND,
	NFQNL_CFG_CMD_PF_BIND,
	NFQNL_CFG_CMD_PF_UNBIND,
};

struct nfqnl_msg_config_cmd {
	u_int8_t	command;	/* nfqnl_msg_config_cmds */
	u_int8_t	_pad;
	u_int16_t	pf;		/* AF_xxx for PF_[UN]BIND */
} __attribute__ ((packed));

enum nfqnl_config_mode {
	NFQNL_COPY_NONE,
	NFQNL_COPY_META,
	NFQNL_COPY_PACKET,
};

struct nfqnl_msg_config_params {
	u_int32_t	copy_range;
	u_int8_t	copy_mode;	/* enum nfqnl_config_mode */
} __attribute__ ((packed));


enum nfqnl_attr_config {
	NFQA_CFG_UNSPEC,
	NFQA_CFG_CMD,			/* nfqnl_msg_config_cmd */
	NFQA_CFG_PARAMS,		/* nfqnl_msg_config_params */
	NFQA_CFG_QUEUE_MAXLEN,		/* u_int32_t */
	__NFQA_CFG_MAX
};
#define NFQA_CFG_MAX (__NFQA_CFG_MAX-1)

*)

implementation

end.

