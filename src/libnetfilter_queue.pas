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
  ctypes, sockets;

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

//function nfq_nfnlh(h : pnfq_handle

(*
extern struct nfnl_handle *nfq_nfnlh(struct nfq_handle *h);
extern int nfq_fd(struct nfq_handle *h);

typedef int  nfq_callback(struct nfq_q_handle *gh, struct nfgenmsg *nfmsg,
		       struct nfq_data *nfad, void *data);


extern struct nfq_handle *nfq_open(void);
extern struct nfq_handle *nfq_open_nfnl(struct nfnl_handle *nfnlh);
extern int nfq_close(struct nfq_handle *h);

extern int nfq_bind_pf(struct nfq_handle *h, u_int16_t pf);
extern int nfq_unbind_pf(struct nfq_handle *h, u_int16_t pf);

extern struct nfq_q_handle *nfq_create_queue(struct nfq_handle *h,
			      			 u_int16_t num,
						 nfq_callback *cb,
						 void *data);
extern int nfq_destroy_queue(struct nfq_q_handle *qh);

extern int nfq_handle_packet(struct nfq_handle *h, char *buf, int len);

extern int nfq_set_mode(struct nfq_q_handle *qh,
			  u_int8_t mode, unsigned int len);

int nfq_set_queue_maxlen(struct nfq_q_handle *qh,
			u_int32_t queuelen);

extern int nfq_set_verdict(struct nfq_q_handle *qh,
			     u_int32_t id,
			     u_int32_t verdict,
			     u_int32_t data_len,
			     const unsigned char *buf);

extern int nfq_set_verdict2(struct nfq_q_handle *qh,
			    u_int32_t id,
			    u_int32_t verdict,
			    u_int32_t mark,
			    u_int32_t datalen,
			    const unsigned char *buf);

extern __attribute__((deprecated))
int nfq_set_verdict_mark(struct nfq_q_handle *qh,
			 u_int32_t id,
			 u_int32_t verdict,
			 u_int32_t mark,
			 u_int32_t datalen,
			 const unsigned char *buf);

/* message parsing function */

extern struct nfqnl_msg_packet_hdr *
				nfq_get_msg_packet_hdr(struct nfq_data *nfad);

extern u_int32_t nfq_get_nfmark(struct nfq_data *nfad);

extern int nfq_get_timestamp(struct nfq_data *nfad, struct timeval *tv);

/* return 0 if not set */
extern u_int32_t nfq_get_indev(struct nfq_data *nfad);
extern u_int32_t nfq_get_physindev(struct nfq_data *nfad);
extern u_int32_t nfq_get_outdev(struct nfq_data *nfad);
extern u_int32_t nfq_get_physoutdev(struct nfq_data *nfad);

extern int nfq_get_indev_name(struct nlif_handle *nlif_handle,
			      struct nfq_data *nfad, char *name);
extern int nfq_get_physindev_name(struct nlif_handle *nlif_handle,
			          struct nfq_data *nfad, char *name);
extern int nfq_get_outdev_name(struct nlif_handle *nlif_handle,
			       struct nfq_data *nfad, char *name);
extern int nfq_get_physoutdev_name(struct nlif_handle *nlif_handle,
				   struct nfq_data *nfad, char *name);

extern struct nfqnl_msg_packet_hw *nfq_get_packet_hw(struct nfq_data *nfad);

/* return -1 if problem, length otherwise */
extern int nfq_get_payload(struct nfq_data *nfad, unsigned char **data);

enum {
	NFQ_XML_HW	= (1 << 0),
	NFQ_XML_MARK	= (1 << 1),
	NFQ_XML_DEV	= (1 << 2),
	NFQ_XML_PHYSDEV	= (1 << 3),
	NFQ_XML_PAYLOAD	= (1 << 4),
	NFQ_XML_TIME	= (1 << 5),
	NFQ_XML_ALL	= ~0U,
};

extern int nfq_snprintf_xml(char *buf, size_t len, struct nfq_data *tb, int flags);
*)

implementation

end.

