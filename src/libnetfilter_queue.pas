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
  unixtype, libnfnetlink, nfnetlink, linux_nfnetlink_queue;

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

function nfq_nfnlh(h : pnfq_handle) : pnfnl_handle;
 cdecl; external NETFILTER_QUEUE_LIB;

function nfq_fd(h : pnfq_handle) : cint;
 cdecl; external NETFILTER_QUEUE_LIB;

type
 nfq_callback = function(gh   : pnfq_q_handle; nfmsg : nfgenmsg;
                         nfad : pnfq_data;     data  : pointer) : cint;   cdecl;

function nfq_open : pnfq_handle;
 cdecl; external NETFILTER_QUEUE_LIB;

function nfq_open_nfnl(nfnlh : pnfnl_handle) : pnfq_handle;
 cdecl; external NETFILTER_QUEUE_LIB;

function nfq_close(h : pnfq_handle) : cint;
 cdecl; external NETFILTER_QUEUE_LIB;

function nfq_bind_pf(h : pnfq_handle; pf : cuint16) : cint;
 cdecl; external NETFILTER_QUEUE_LIB;

function nfq_unbind_pf(h : pnfq_handle; pf : cuint16) : cint;
 cdecl; external NETFILTER_QUEUE_LIB;

function nfq_create_queue(h    : pnfq_handle;
                          num  : cuint16;
                          cb   : nfq_callback;
                          data : pointer)       : pnfq_q_handle;
 cdecl; external NETFILTER_QUEUE_LIB;

function nfq_destroy_queue(qh : pnfq_q_handle) : cint;
 cdecl; external NETFILTER_QUEUE_LIB;

function nfq_handle_packet(h   : pnfq_handle;
                           buf : PChar;
                           len : cint)        : cint;
 cdecl; external NETFILTER_QUEUE_LIB;

function nfq_set_mode(qh   : nfq_q_handle;
                      mode : cuint8;
                      len  : cuint)       : cint;
 cdecl; external NETFILTER_QUEUE_LIB;

function nfq_set_queue_maxlen(qh       : pnfq_q_handle;
                              queuelen : cuint32)       : cint;
 cdecl; external NETFILTER_QUEUE_LIB;

function nfq_set_verdict(qh       : pnfq_q_handle;
                         id       : cuint32;
                         verdict  : cuint32;
                         data_len : cuint32;
                         buf      : PChar)          : cint;
 cdecl; external NETFILTER_QUEUE_LIB;

function nfq_set_verdict2(qh      : pnfq_q_handle;
                          id      : cuint32;
                          verdict : cuint32;
                          mark    : cuint32;
                          datalen : cuint32;
                          buf     : PChar)          : cint;
 cdecl; external NETFILTER_QUEUE_LIB;

function nfq_set_verdict_mark(qh      : pnfq_q_handle;
                              id      : cuint32;
                              verdict : cuint32;
                              mark    : cuint32;
                              dataleb : cuint32;
                              buf     : PChar)          : cint;
 cdecl; external NETFILTER_QUEUE_LIB; deprecated;

// message parsing function

function nfq_get_msg_packet_hdr(nfad : pnfq_data) : pnfqnl_msg_packet_hdr;
 cdecl; external NETFILTER_QUEUE_LIB;

function nfq_get_nfmark(nfad : pnfq_data) : cuint32;
 cdecl; external NETFILTER_QUEUE_LIB;

function nfq_get_timestamp(nfad : pnfq_data; tv : ptimeval) : cint;
 cdecl; external NETFILTER_QUEUE_LIB;

// return 0 if not set

function nfq_get_indev(nfad : pnfq_data) : cuint32;
 cdecl; external NETFILTER_QUEUE_LIB;

function nfq_get_physindev(nfad : pnfq_data) : cuint32;
 cdecl; external NETFILTER_QUEUE_LIB;

function nfq_get_outdev(nfad : pnfq_data) : cuint32;
 cdecl; external NETFILTER_QUEUE_LIB;

function nfq_get_physoutdev(nfad : pnfq_data) : cuint32;
 cdecl; external NETFILTER_QUEUE_LIB;

function nfq_get_indev_name(nlif_handle : pnlif_handle;
                            nfad        : pnfq_data;
                            name        : PChar)         : cint;
 cdecl; external NETFILTER_QUEUE_LIB;

function nfq_get_physindev_name(nlif_handle : pnlif_handle;
                                nfad        : pnfq_data;
                                name        : PChar)         : cint;
 cdecl; external NETFILTER_QUEUE_LIB;

function nfq_get_outdev_name(nlif_handle : pnlif_handle;
                             nfad        : pnfq_data;
                             name        : PChar)         : cint;
 cdecl; external NETFILTER_QUEUE_LIB;

function nfq_get_physoutdev_name(nlif_handle : pnlif_handle;
                                 nfad        : pnfq_data;
                                 name        : PChar)         : cint;
 cdecl; external NETFILTER_QUEUE_LIB;

function nfq_get_packet_hw(nfad : pnfq_data) : pnfqnl_msg_packet_hw;
 cdecl; external NETFILTER_QUEUE_LIB;

//return -1 if problem, length otherwise
function nfq_get_payload(nfad : pnfq_data;
                         data : ppchar)     : cint;
 cdecl; external NETFILTER_QUEUE_LIB;

const
 NFQ_XML_HW      = 1 shl 0;
 NFQ_XML_MARK    = 1 shl 1;
 NFQ_XML_DEV     = 1 shl 2;
 NFQ_XML_PHYSDEV = 1 shl 3;
 NFQ_XML_PAYLOAD = 1 shl 4;
 NFQ_XML_TIME    = 1 shl 5;
 NFQ_XML_ALL     = cuint(not 0);

function nfq_snprintf_xml(buf   : PChar;
                          len   : size_t;
                          tb    : pnfq_data;
                          flags : cint)      : cint;
cdecl; external NETFILTER_QUEUE_LIB;

implementation

end.

