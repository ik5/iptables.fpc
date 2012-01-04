unit linux_nfnetlink_compat;

{$mode fpc}{$packrecords c}

interface

uses
  ctypes;

const
 (* nfnetlink groups: Up to 32 maximum *)

 NF_NETLINK_CONNTRACK_NEW         = $00000001;
 NF_NETLINK_CONNTRACK_UPDATE      = $00000002;
 NF_NETLINK_CONNTRACK_DESTROY     = $00000004;
 NF_NETLINK_CONNTRACK_EXP_NEW     = $00000008;
 NF_NETLINK_CONNTRACK_EXP_UPDATE  = $00000010;
 NF_NETLINK_CONNTRACK_EXP_DESTROY = $00000020;

(* Generic structure for encapsulation optional netfilter information.
 * It is reminiscent of sockaddr, but with sa_family replaced
 * with attribute type.
 * ! This should someday be put somewhere generic as now rtnetlink and
 * ! nfnetlink use the same attributes methods. - J. Schulist.
 *)

type
  pnfattr = ^nfattr;
  nfattr  = record
    nfa_len  : cuint16;
    nfa_type : cuint16; (* we use 15 bits for the type, and the highest
                           bit to indicate whether the payload is nested *)
  end;

(* FIXME: Apart from NFNL_NFA_NESTED shamelessly copy and pasted from
 * rtnetlink.h, it's time to put this in a generic file *)

const
 NFNL_NFA_NEST = $8000;

function NFA_TYPE(attr : nfattr) : cuint16; inline; cdecl;

const
 NFA_ALIGNTO = 4;

function NFA_ALIGN(len : cuint16) : cuint16; inline; cdecl;
function NFA_OK(nfa : nfattr; len : cuint16) : Boolean; inline; cdecl;
function NFA_NEXT(nfa : nfattr; var attrlen : cuint16) : pnfattr; inline; cdecl;
function NFA_LENGTH(len : cuint16) : cuint16; inline; cdecl;
function NFA_SPACE(len : cuint16) : cuint16; inline; cdecl;
function NFA_DATA(nfa : nfattr) : pointer; inline; cdecl;
function NFA_PAYLOAD(nfa : nfattr) : cint; inline; cdecl;

(*
#define NFA_NEST(skb, type) \
({	struct nfattr *__start = (struct nfattr * )skb_tail_pointer(skb); \
	NFA_PUT(skb, (NFNL_NFA_NEST | type), 0, NULL); \
	__start;  })
#define NFA_NEST_END(skb, start) \
({      (start)->nfa_len = skb_tail_pointer(skb) - (unsigned char * )(start); \
        (skb)->len; })
#define NFA_NEST_CANCEL(skb, start) \
({      if (start) \
                skb_trim(skb, (unsigned char * ) (start) - (skb)->data); \
        -1; })

#define NFM_NFA(n)      ((struct nfattr * )(((char * )(n)) \
        + NLMSG_ALIGN(sizeof(struct nfgenmsg))))
#define NFM_PAYLOAD(n)  NLMSG_PAYLOAD(n, sizeof(struct nfgenmsg))

#endif /* ! __KERNEL__ */
#endif /* _NFNETLINK_COMPAT_H */
*)

implementation

function NFA_TYPE(attr: nfattr): cuint16; cdecl;
begin
// #define NFA_TYPE(attr) 	((attr)->nfa_type & 0x7fff)
  NFA_TYPE := attr.nfa_type and $7fff;
end;

function NFA_ALIGN(len: cuint16): cuint16; cdecl;
begin
// #define NFA_ALIGN (len)	(((len) + NFA_ALIGNTO - 1) & ~(NFA_ALIGNTO - 1))
  NFA_ALIGN := (len + NFA_ALIGNTO -1) and not (NFA_ALIGNTO - 1);
end;

function NFA_OK(nfa: nfattr; len: cuint16): Boolean; cdecl;
begin
// #define (nfa,len)	((len) > 0 && (nfa)->nfa_len >= sizeof(struct nfattr) \
//	&& (nfa)->nfa_len <= (len))
  NFA_OK := (len > 0) and (nfa.nfa_len >= sizeof(nfattr)) and
             (nfa.nfa_len <= len);
end;

function NFA_NEXT(nfa: nfattr; var attrlen: cuint16): pnfattr; cdecl;
begin
// #define NFA_NEXT(nfa,attrlen)	((attrlen) -= NFA_ALIGN((nfa)->nfa_len), \
//	(struct nfattr * )(((char * )(nfa)) + NFA_ALIGN((nfa)->nfa_len)))
 dec(attrlen, NFA_ALIGN(nfa.nfa_len));
 NFA_NEXT := @nfa + nfa.nfa_len;
end;

function NFA_LENGTH(len: cuint16): cuint16; cdecl;
begin
// #define NFA_LENGTH(len)	(NFA_ALIGN(sizeof(struct nfattr)) + (len))
 NFA_LENGTH := NFA_ALIGN(sizeof(nfattr)) + len;
end;

function NFA_SPACE(len: cuint16): cuint16; cdecl;
begin
// #define NFA_SPACE(len)	NFA_ALIGN(NFA_LENGTH(len))
 NFA_SPACE := NFA_ALIGN(NFA_LENGTH(len));
end;

function NFA_DATA(nfa: nfattr): pointer; cdecl;
begin
// #define NFA_DATA(nfa)   ((void * )(((char * )(nfa)) + NFA_LENGTH(0)))
 NFA_DATA := Pointer(@nfa + NFA_LENGTH(0));
end;

function NFA_PAYLOAD(nfa: nfattr): cint; cdecl;
begin
// #define NFA_PAYLOAD(nfa) ((int)((nfa)->nfa_len) - NFA_LENGTH(0))
 NFA_PAYLOAD := nfa.nfa_len - NFA_LENGTH(0);
end;

end.

