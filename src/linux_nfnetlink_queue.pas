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
   hook        : cuint8;   // netfilter hook
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

type
 nfqnl_attr_type = cint;

const
 NFQA_UNSPEC             = 0;
 NFQA_PACKET_HDR         = 1;
 NFQA_VERDICT_HDR        = 2;  // nfqnl_msg_verdict_hrd
 NFQA_MARK               = 4;  // u_int32_t nfmark
 NFQA_TIMESTAMP          = 5;  // nfqnl_msg_packet_timestamp
 NFQA_IFINDEX_INDEV      = 6;  // u_int32_t ifindex
 NFQA_IFINDEX_OUTDEV     = 7;  // u_int32_t ifindex
 NFQA_IFINDEX_PHYSINDEV  = 8;  // u_int32_t ifindex
 NFQA_IFINDEX_PHYSOUTDEV = 9;  // u_int32_t ifindex
 NFQA_HWADDR             = 10; // nfqnl_msg_packet_hw
 NFQA_PAYLOAD            = 11; // opaque data payload
 __NFQA_MAX              = 12;
 NFQA_MAX                = __NFQA_MAX;

type
 pnfqnl_msg_verdict_hdr = ^nfqnl_msg_verdict_hdr;
 nfqnl_msg_verdict_hdr  = packed record
   verdict : cuint32;
   id      : cuint32;
 end;

const
 NFQNL_CFG_CMD_NONE      = 0;
 NFQNL_CFG_CMD_BIND      = 1;
 NFQNL_CFG_CMD_UNBIND    = 2;
 NFQNL_CFG_CMD_PF_BIND   = 3;
 NFQNL_CFG_CMD_PF_UNBIND = 4;

type
 pnfqnl_msg_config_cmd = ^nfqnl_msg_config_cmd;
 nfqnl_msg_config_cmd  = packed record
   command : cuint8;  // nfqnl_msg_config_cmds
   _pad    : cuint8;
   pf      : cuint16; // AF_xxx for PF_[UN]BIND
 end;

 nfqnl_config_mode = cint;

const
 NFQNL_COPY_NONE   = 0;
 NFQNL_COPY_META   = 1;
 NFQNL_COPY_PACKET = 2;

type
 pnfqnl_msg_config_params = ^nfqnl_msg_config_params;
 nfqnl_msg_config_params  = packed record
   copy_range : cuint32;
   copy_mode  : cuint8;  // enum nfqnl_config_mode
 end;

 nfqnl_attr_config = cint;

const
  NFQA_CFG_UNSPEC       = 0;
  NFQA_CFG_CMD          = 1; // nfqnl_msg_config_cmd
  NFQA_CFG_PARAMS       = 2; // nfqnl_msg_config_params
  NFQA_CFG_QUEUE_MAXLEN = 3; // u_int32_t
  __NFQA_CFG_MAX        = 4;
  NFQA_CFG_MAX          = __NFQA_CFG_MAX -1;

implementation

end.

