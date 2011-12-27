{$IFNDEF LINUX}
   {$ERROR This unit can work only with Linux - It requires iptables that are part of the Linux kernel}
{$ENDIF}
unit x_tables;

{$mode fpc}{$packrecords c}

interface

uses
  ctypes;

const
  XT_FUNCTION_MAXNAMELEN  = 30;
  XT_EXTENSION_MAXNAMELEN = 29;
  XT_TABLE_MAXNAMELEN     = 32;

{$IF not defined(NF_REPEAT)}
  NF_REPEAT               = 4;
{$ENDIF}

type
  pxt_match  = ^xt_match;
  xt_match   = record end;
  pxt_target = ^xt_target;
  xt_target  = record end;

  ___match_u = record // Internal record, to seperate the union parts ...
    case Integer of
      0 : ( user : record
              match_size : cuint16;
              // Used by userspace
              name       : array[0..XT_EXTENSION_MAXNAMELEN -1] of char;
              revision   : cuint8;
            end;
          );
      1 : (
            kernel : record
              match_size : cuint16;
              // used inside the kernel
              match      : pxt_match;
            end;
          );
      2 : (
            match_size : cuint16;
          );
  end;

  ppxt_entry_match = ^pxt_entry_match;
  pxt_entry_match  = ^xt_entry_match;
  xt_entry_match   = record
    u    : ___match_u;
    data : array[0..0] of Byte;
  end;

  ___target_u = record  // internal record for seperating unions
    case Integer of
      0 : ( match_size0 : cuint16;
            // Used by userspace
            name        : array[0..XT_EXTENSION_MAXNAMELEN-1] of char;
            revision    : cuint8;
          );
      1 : (
            match_size1 : cuint16;
            // Used inside the kernel
            target      : pxt_target;
          );
      2 : ( // Total length
            match_size2 : cuint16;
          );
  end;

  ppxt_entry_target = ^pxt_entry_target;
  pxt_entry_target  = ^xt_entry_target;
  xt_entry_target   = record
     u    : ___target_u;
     data : array[0..0] of char;
  end;

(*

#define XT_TARGET_INIT(__name, __size)					       \
{									       \
	.target.u.user = {						       \
		.target_size	= XT_ALIGN(__size),			       \
		.name		= __name,				       \
	},								       \
}

*)

  pxt_standard_target = ^xt_standard_target;
  xt_standard_target  = record
     target  : xt_entry_target;
     verdict : cint;
  end;

  pxt_error_target = ^xt_error_target;
  xt_error_target  = record
    target    : xt_entry_target;
    errorname : array[0..XT_FUNCTION_MAXNAMELEN-1] of char;
  end;

  pxt_get_revision = ^xt_get_revision;
  (* The argument to IPT_SO_GET_REVISION_*.  Returns highest revision
   * kernel supports, if >= revision. *)
  xt_get_revision  = record
    name     : array[0..XT_FUNCTION_MAXNAMELEN-1] of char;
    revision : cuint8;
  end;

const
  // CONTINUE verdict for targets
  XT_CONTINUE = $FFFFFFFF;
  // For standard target
  XT_RETURN   = -NF_REPEAT - 1;

type
(* this is a dummy structure to find out the alignment requirement for a struct
 * containing all the fundamental data types that are used in ipt_entry,
 * ip6t_entry and arpt_entry.  This sucks, and it is a hack.  It will be my
 * personal pleasure to remove it -HW
 *)

 p_xt_align = ^_xt_align ;
 _xt_align  = record
   u8  : cuint8;
   u16 : cuint16;
   u32 : cuint32;
   u64 : cuint64;
 end;

(*
#define XT_ALIGN(s) __ALIGN_KERNEL((s), __alignof__(struct _xt_align))
*)

const
  // Standard return verdict, or do jump.
  XT_STANDARD_TARGET_ = '';
  // Error verdict.
  XT_ERROR_TARGET_    = 'ERROR';

type
 pxt_counters = ^xt_counters;
 xt_counters  = record
   // Packet and byte counters
   pcnt, bcnt : cuint64;
 end;

procedure set_counter(c : xt_counters; b,p : cuint64); inline; cdecl;
procedure add_counter(c : xt_counters; b,p : cuint64); inline; cdecl;

type
 pxt_counters_info = ^xt_counters_info;
 // The argument to IPT_SO_ADD_COUNTERS.
 xt_counters_info  = record
   // which table
   name         : array[0..XT_TABLE_MAXNAMELEN-1] of char;
   num_counters : cuint;
   // The counters (actually `number' of these).
   counters     : array[0..0] of xt_counters;
 end;

const
  XT_INV_PROTO = $40; // Invert the sense of PROTO.

(*
/* fn returns 0 to continue iteration */
#define XT_MATCH_ITERATE(type, e, fn, args...)			\
({								\
	unsigned int __i;					\
	int __ret = 0;						\
	struct xt_entry_match *__m;				\
								\
	for (__i = sizeof(type);				\
	     __i < (e)->target_offset;				\
	     __i += __m->u.match_size) {			\
		__m = (void * )e + __i;				\
								\
		__ret = fn(__m , ## args);			\
		if (__ret != 0)					\
			break;					\
	}							\
	__ret;							\
})


/* fn returns 0 to continue iteration */
#define XT_ENTRY_ITERATE_CONTINUE(type, entries, size, n, fn, args...) \
({								\
	unsigned int __i, __n;					\
	int __ret = 0;						\
	type *__entry;						\
								\
	for (__i = 0, __n = 0; __i < (size);			\
	     __i += __entry->next_offset, __n++) { 		\
		__entry = (void * )(entries) + __i;		\
		if (__n < n)					\
			continue;				\
								\
		__ret = fn(__entry , ## args);			\
		if (__ret != 0)					\
			break;					\
	}							\
	__ret;							\
})

/* fn returns 0 to continue iteration */
#define XT_ENTRY_ITERATE(type, entries, size, fn, args...) \
	XT_ENTRY_ITERATE_CONTINUE(type, entries, size, 0, fn, args)


/* pos is normally a struct ipt_entry/ip6t_entry/etc. */
#define xt_entry_foreach(pos, ehead, esize) \
	for ((pos) = (typeof(pos))(ehead); \
	     (pos) < (typeof(pos))((char * )(ehead) + (esize)); \
	     (pos) = (typeof(pos))((char * )(pos) + (pos)->next_offset))

/* can only be xt_entry_match, so no use of typeof here */
#define xt_ematch_foreach(pos, entry) \
	for ((pos) = (struct xt_entry_match * )entry->elems; \
	     (pos) < (struct xt_entry_match * )((char * )(entry) + \
	             (entry)->target_offset); \
	     (pos) = (struct xt_entry_match * )((char * )(pos) + \
	             (pos)->u.match_size))


*)

implementation

procedure set_counter(c: xt_counters; b, p: cuint64); cdecl;
begin
// #define SET_COUNTER(c,b,p) do { (c).bcnt = (b); (c).pcnt = (p); } while(0)
 repeat
  c.bcnt := b;
  c.pcnt := p;
 until true;
end;

procedure add_counter(c: xt_counters; b, p: cuint64); cdecl;
begin
// #define ADD_COUNTER(c,b,p) do { (c).bcnt += (b); (c).pcnt += (p); } while(0)
 repeat
   inc(c.bcnt, b);
   inc(c.pcnt, p);
 until true;
end;

end.

