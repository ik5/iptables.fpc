{ translation of linux/netfilter_ipv4/ip_queue.h

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
unit ip_queue;

{$mode fpc}{$packrecords c}

interface

uses
  ctypes;

type
 pipq_packet_msg = ^ipq_packet_msg;
 // Messages sent from kernel
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

 pipq_mode_msg = ^ipq_mode_msg;
 ipq_mode_msg  = record
   value : PChar;   // Requested mode
   range : csize_t; // Optional range of packet requested
 end;
 pipq_mode_msg_t = ^ipq_mode_msg_t;
 ipq_mode_msg_t  = ipq_packet_msg_t;

 pipq_verdict_msg = ^ipq_verdict_msg;
 ipq_verdict_msg  = record
   value    : cuint;               // Verdict to hand to netfilter
   id       : culong;              // Packet ID for this verdict
   data_len : csize_t;             // Length of replacement data
   payload  : array[0..0] of char; // Optional replacement packet
 end;
 pipq_verdict_msg_t = ^ipq_verdict_msg_t;
 ipq_verdict_msg_t  = ipq_verdict_msg;

 pipq_peer_msg = ^ipq_peer_msg;
 ipq_peer_msg  = record
   case msg : integer of
    0 : (verdict : ipq_verdict_msg_t);
    1 : (mode    : ipq_mode_msg_t);
 end;
 pipq_peer_msg_t = ^ipq_peer_msg_t;
 ipq_peer_msg_t  = ipq_peer_msg;

// Packet delivery modes
const
 IPQ_COPY_NONE   = 0; // Initial mode, packets are dropped
 IPQ_COPY_META   = 1; // Copy metadata
 IPQ_COPY_PACKET = 2; // Copy metadata + packet (range)
 IPQ_COPY_MAX    = IPQ_COPY_PACKET;

 // Types of messages
 IPQM_BASE    = $10;          // standard netlink messages below this
 IPQM_MODE    = IPQM_BASE +1; // Mode request from peer
 IPQM_VERDICT = IPQM_BASE +2; // Verdict from peer
 IPQM_PACKET  = IPQM_BASE +3; // Packet from kernel
 IPQM_MAX     = IPQM_BASE +4;


implementation

end.

