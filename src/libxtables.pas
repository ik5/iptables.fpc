{$IFNDEF LINUX}
   {$ERROR This unit can work only with Linux - It requires iptables that are part of the Linux kernel}
{$ENDIF}
unit libxtables;

{$mode fpc}{$packrecord c}

interface

uses
  ctypes, sockets, x_tables, netfilter;

const
  XTABLES_LIB = 'libxtables';

const
{$IF not defined(IPPROTO_SCTP)}
  IPPROTO_SCTP = 132;
{$ENDIF}

{$IF not defined(IPPROTO_DCCP)}
  IPPROTO_DCCP = 33;
{$ENDIF}

{$IF not defined(IPPROTO_MH)}
  IPPROTO_MH = 135;
{$ENDIF}

{$IF not defined(IPPROTO_UDPLITE)}
  IPPROTO_UDPLITE = 136;
{$ENDIF}

  XTABLES_VERSION      = 'libxtables.so.7';
  XTABLES_VERSION_CODE = 7;

type
{$IF not defined(option)}
  ppoption = ^poption;
  poption  = ^option;
  option   = record end;
{$ENDIF}

  (**
   * Select the format the input has to conform to, as well as the target type
   * (area pointed to with XTOPT_POINTER). Note that the storing is not always
   * uniform. @cb->val will be populated with as much as there is space, i.e.
   * exactly 2 items for ranges, but the target area can receive more values
   * (e.g. in case of ranges), or less values (e.g. %XTTYPE_HOSTMASK).
   *)
  xt_option_type = cint;

const
  XTTYPE_NONE        =  0; // option takes no argument
  XTTYPE_UINT8       =  1; // standard integer
  XTTYPE_UINT16      =  2; // standard integer
  XTTYPE_UINT32      =  3; // standard integer
  XTTYPE_UINT64      =  4; // standard integer
  XTTYPE_UINT8RC     =  5; // colon-separated range of standard integers
  XTTYPE_UINT16RC    =  6; // colon-separated range of standard integers
  XTTYPE_UINT32RC    =  7; // colon-separated range of standard integers
  XTTYPE_UINT64RC    =  8; // colon-separated range of standard integers
  XTTYPE_DOUBLE      =  9; // double-precision floating point number
  XTTYPE_STRING      = 10; // arbitrary string
  XTTYPE_TOSMASK     = 11; // 8-bit TOS value with optional mask
  XTTYPE_MARKMASK32  = 12; // 32-bit mark with optional mask
  XTTYPE_SYSLOGLEVEL = 13; // syslog level by name or number
  XTTYPE_HOST        = 14; // one host or address (ptr: union nf_inet_addr)
  XTTYPE_HOSTMASK    = 15; { one host or address, with an optional prefix length
                             (ptr: union nf_inet_addr; only host portion is stored) }
  XTTYPE_PROTOCOL    = 16; // protocol number/name from /etc/protocols (ptr: uint8_t)
  XTTYPE_PORT        = 17; // 16-bit port name or number (supports %XTOPT_NBO)
  XTTYPE_PORTRC      = 18; // colon-separated port range (names acceptable), (supports %XTOPT_NBO)
  XTTYPE_PLEN        = 19; // prefix length
  XTTYPE_PLENMASK    = 20; // prefix length (ptr: union nf_inet_addr)
  XTTYPE_ETHERMAC    = 21; // Ethernet MAC address in hex form

type
  xt_option_flags = cint;

const
  XTOPT_INVERT = 1 shl 0; // option is invertible (usable with !)
	XTOPT_MAND   = 1 shl 1; // option is mandatory
	XTOPT_MULTI  = 1 shl 2; // option may be specified multiple times
	XTOPT_PUT    = 1 shl 3; // store value into memory at @ptroff
	XTOPT_NBO    = 1 shl 4; { store value in network-byte order
                          (only certain XTTYPEs recognize this) }

type
  pxt_option_entry = ^xt_option_entry;
  xt_option_entry  = record
    name   : PChar;          // name of option
    type_  : xt_option_type; // type of input and validation method, see %XTTYPE_*
    id,                      // unique number (within extension) for option, 0-31
    excl,                    // bitmask of flags that cannot be used with this option
    also,                    // bitmask of flags that must be used with this option
    flags  : cuint;          // bitmask of option flags, see %XTOPT_*
    ptroff : cuint;          // offset into private structure for member
    size   : csize_t;        // size of the item pointed to by @ptroff; this is a safeguard
    min,                     // lowest allowed value (for singular integral types)
    max    : cuint;          // highest allowed value (for singular integral types)
  end;

  ____option_val = record // for internal usage only due to the union
    case val : Integer of
     0 : (
            u8           : cuint8;
            u8_range     : array[Boolean] of cuint;
            syslog_level : cuint;
            protocol     : cuint;
         );
     1 : (
           u16        : cuint16;
           u16_range  : array[Boolean] of cuint16;
           port       : cuint16;
           port_range : array[Boolean] of cuint16;
         );
     2 : (
           u32       : cuint32;
           u32_range : array[Boolean] of cuint32;
         );
     3 : (
           u64       : cuint64;
           u64_range : array[Boolean] of cuint64;
         );
     4 : (
           dbl : cdouble;
         );
     5 : (
           haddr, hmask : nf_inet_addr;
           hlen         : cuint8;
         );
     6 : (
           tos_value, tos_mask : cuint8;
         );
     7 : (
           mark, mask : cuint32;
         );
     8 : (
           ethermac : array[0..5] of cuint8;
         );
  end;

  ____option_entry = record
    case integer of
     0 : ( match  : ppxt_entry_match);
     1 : ( target : ppxt_entry_target);
  end;

  pxt_option_call = ^xt_option_call;
  xt_option_call  = record
    arg,                         // input from command line
    ext_name : PChar;            // name of extension currently being processed
    entry    : pxt_option_entry; // current option being processed
    data     : pointer;          // per-extension kernel data block
    xflags   : cuint;            // options of the extension that have been used
    invert   : cbool;            // whether option was used with !
    nvals    : cuint8;           // number of results in uXX_multi
    val      : ____option_val;   // parsed result
    //Wished for a world where the ones below were gone:
    union    : ____option_entry;
    xt_entry : pointer;
    udata    : pointer;          // parsed result (cf. xtables_{match,target}->udata_size)
  end;

  pxt_fcheck_call = ^xt_fcheck_call;
  xt_fcheck_call  = record
    ext_name : PChar;   // name of extension currently being processed
    data,               // per-extension (kernel) data block
    udata    : pointer; { per-extension private scratch area
                          (cf. xtables_{match,target}->udata_size) }
    xflags   : cuint;   // options of the extension that have been used
  end;

  pxtables_lmap = ^xtables_lmap;
  // A "linear"/linked-list based name<->id map, for files similar to /etc/iproute2/
  xtables_lmap  = record
    name : PChar;
    id   : cint;
    next : pxtables_lmap;
  end;

  ppxtables_match = ^pxtables_match;
  pxtables_match  = ^xtables_match;
  // Include file for additions: new matches and targets.
  xtables_match   = record
   (*
	  * ABI/API version this module requires. Must be first member,
	  * as the rest of this struct may be subject to ABI changes.
	  *)
    version       : PChar;
    next          : pxtables_match;
    name          : PChar;
    // Revision of match (0 by default).
    revision      : cuint8;
    family        : cuint16;
    // Size of match data.
    size          : csize_t;
    // Size of match data relevent for userspace comparison purposes
    userspacesize : csize_t;
    // Function which prints out usage message.
    help          : procedure; cdecl;
    // Function which prints out usage message.
    init          : procedure(m : pxt_entry_match); cdecl;
    (* Function which parses command options; returns true if it ate an option
       entry is struct ipt_entry for example
    *)
    parse         : function(c      : cint;
                             argv   : PPChar;
                             invert : cint;
                             flags  : cuint;
                             entry  : Pointer;
                             match  : ppxt_entry_match) : cint; cdecl;
    // Final check; exit if not ok.
    final_check   : procedure (flags   : cuint); cdecl;
    (*
      Prints out the match iff non-NULL: put space at end
    	ip is struct ipt_ip * for example
    *)
    print         : procedure (ip      : pointer;
                               match   : pxt_entry_match;
                               numeric : cint); cdecl;
    (*
      Saves the match info in parsable form to stdout.
	    ip is struct ipt_ip * for example
    *)
    save          : procedure (ip      : pointer;
                               match   : pxt_entry_match); cdecl;
    // Pointer to list of extra command-line options
    extra_opts    : poption;
    // New parser
    x6_parse      : procedure(p : pxt_option_call); cdecl;
    x6_fcheck     : procedure(p : pxt_fcheck_call); cdecl;
    x6_options    : pxt_option_entry;
    // Size of per-extension instance extra "global" scratch space
    udata_size    : csize_t;
    //Ignore these men behind the curtain:
    udata         : pointer;
    option_offset : cuint;
    m             : pxt_entry_match;
    mflags        : cuint;
    loaded        : cuint; // simulate loading so options are merged properly
  end;

  ppxtables_target = ^pxtables_target;
  pxtables_target  = ^xtables_target;
  xtables_target   = record
    (*
     * ABI/API version this module requires. Must be first member,
  	 * as the rest of this struct may be subject to ABI changes.
     *)
    version        : PChar;
    next           : pxtables_target;
    name           : PChar;
    // Revision of target (0 by default).
    revision       : cuint8;
    family         : cuint16;
    // Size of target data.
    size           : csize_t;
    // Size of target data relevent for userspace comparison purposes
    userspacesize : csize_t;
    // Function which prints out usage message.
    help          : procedure; cdecl;
    // Initialize the target.
    init          : procedure(t : pxt_entry_target); cdecl;
    (*
       Function which parses command options; returns true if it ate an option
       entry is struct ipt_entry for example
    *)
    parse         : function(c          : cint;
                             argv       : PPChar;
                             invert     : cint;
                             flags      : pcuint;
                             entry      : Pointer;
                             targetinfo : ppxtables_target) : cint; cdecl;
    // Final check; exit if not ok.
    final_check   : procedure(flags : cuint); cdecl;
    // Prints out the target iff non-NULL: put space at end
    print         : procedure(ip      : pointer;
                              target  : pxt_entry_target;
                              numeric : cint); cdecl;
    // Saves the targinfo in parsable form to stdout.
    save          : procedure(ip     : pointer;
                              target : pxt_entry_target); cdecl;
    // Pointer to list of extra command-line options
    extra_opts    : poption;
    // New parser
    x6_parse      : procedure(p : pxt_option_call); cdecl;
    x6_fcheck     : procedure(p : pxt_fcheck_call); cdecl;
    x6_options    : pxt_option_entry;
    udata_size    : csize_t;
    // Ignore these men behind the curtain:
    udata         : pointer;
    option_offset : cuint;
    t             : pxt_entry_target;
    tflags        : cuint;
    used          : cuint;
    loaded        : cuint; // simulate loading so options are merged properly
  end;

  ppxtables_rule_match = ^pxtables_rule_match;
  pxtables_rule_match  = ^xtables_rule_match;
  xtables_rule_match   = record
    next      : pxtables_rule_match;
    match     : pxtables_match;
    (*
      Multiple matches of the same type: the ones before
 	    the current one are completed from parsing point of view
     *)
    completed : cbool;
  end;

  pxtables_pprot = ^xtables_pprot;
  (**
   * struct xtables_pprot -
   *
   * A few hardcoded protocols for 'all' and in case the user has no
   * /etc/protocols.
   *)
  xtables_pprot  = record
    name : PChar;
    num  : cuint8;
  end;

  xtables_tryload  = cint;
  xtables_exittype = cint;

const
  XTF_DONT_LOAD         = 0;
  XTF_DURING_LOAD       = 1;
  XTF_TRY_LOAD          = 2;
  XTF_LOAD_MUST_SUCCEED = 3;

  OTHER_PROBLEM         = 1;
  PARAMETER_PROBLEM     = 2;
  VERSION_PROBLEM       = 3;
  RESOURCE_PROBLEM      = 4;
  XTF_ONLY_ONCE         = 5;
  XTF_NO_INVERT         = 6;
  XTF_BAD_VALUE         = 7;
  XTF_ONE_ACTION        = 8;

type
  pxtables_globals = ^xtables_globals;
  xtables_globals  = record
    option_offset   : cuint;
    program_name,
    program_version : PChar;
    orig_opts,
    opts            : poption;
    exit_err        : procedure(status : xtables_exittype;
                                msg    : PChar);           cdecl; varargs;
    (*
       varargs exists from FPC 2.6.0 afaik, it allow us to do 1,2,3 instead of
       [1,2,3]. It arrives only with cdecl; prior to it.
       http://freepascal.org/docs-html/ref/refsu77.html
     *)
  end;

(*
#define XT_GETOPT_TABLEEND {.name = NULL, .has_arg = false}
*)

function xtables_modprobe_program : PChar;
 cdecl; external XTABLES_LIB;

function xtables_matches : pxtables_match;
 cdecl; external XTABLES_LIB;

function xtables_targets : pxtables_target;
 cdecl; external XTABLES_LIB;

procedure xtables_init;
 cdecl; external XTABLES_LIB;

procedure xtables_set_nfproto(p : cuint8);
 cdecl; external XTABLES_LIB;

function xtables_calloc(p1, p2 : csize_t) : pointer;
 cdecl; external XTABLES_LIB;

function xtables_malloc(p1 : csize_t) : pointer;
 cdecl; external XTABLES_LIB;

function xtables_realloc(p1 : pointer; p2 : csize_t) : pointer;
 cdecl; external XTABLES_LIB;

function xtables_insmod(p1, p2 : PChar; p3 : cbool) : cint;
 cdecl; external XTABLES_LIB;

function xtables_load_ko(p1 : PChar; p2 : cbool) : cint;
 cdecl; external XTABLES_LIB;

function xtables_set_params(xtp : pxtables_globals) : cint;
 cdecl; external XTABLES_LIB;

procedure xtables_free_opts(reset_offset : cint);
 cdecl; external XTABLES_LIB;

function xtables_merge_options(origopts, oldopts, newopts : poption;
                               option_offset              : pcuint) : poption;
 cdecl; external XTABLES_LIB;

function xtables_init_all(xtp : pxtables_globals; nfproto : cuint8) : cuint;
 cdecl; external XTABLES_LIB;

function xtables_find_match(name    : PChar;
                            tryload : xtables_tryload;
                            match   : ppxtables_rule_match) : pxtables_match;
 cdecl; external XTABLES_LIB;

function xtables_find_target(name : PChar; tryload : xtables_tryload) : pxtables_target;
 cdecl; external XTABLES_LIB;

(*
/* Your shared library should call one of these. */
extern void xtables_register_match(struct xtables_match *me);
extern void xtables_register_matches(struct xtables_match *, unsigned int);
extern void xtables_register_target(struct xtables_target *me);
extern void xtables_register_targets(struct xtables_target *, unsigned int);

extern bool xtables_strtoul(const char *, char **, uintmax_t *,
	uintmax_t, uintmax_t);
extern bool xtables_strtoui(const char *, char **, unsigned int *,
	unsigned int, unsigned int);
extern int xtables_service_to_port(const char *name, const char *proto);
extern u_int16_t xtables_parse_port(const char *port, const char *proto);
extern void
xtables_parse_interface(const char *arg, char *vianame, unsigned char *mask);

/* this is a special 64bit data type that is 8-byte aligned */
#define aligned_u64 u_int64_t __attribute__((aligned(8)))

extern struct xtables_globals *xt_params;
#define xtables_error (xt_params->exit_err)

extern void xtables_param_act(unsigned int, const char *, ...);

extern const char *xtables_ipaddr_to_numeric(const struct in_addr * );
extern const char *xtables_ipaddr_to_anyname(const struct in_addr * );
extern const char *xtables_ipmask_to_numeric(const struct in_addr * );
extern struct in_addr *xtables_numeric_to_ipaddr(const char * );
extern struct in_addr *xtables_numeric_to_ipmask(const char * );
extern void xtables_ipparse_any(const char *, struct in_addr **,
	struct in_addr *, unsigned int * );
extern void xtables_ipparse_multiple(const char *, struct in_addr **,
	struct in_addr **, unsigned int * );

extern struct in6_addr *xtables_numeric_to_ip6addr(const char * );
extern const char *xtables_ip6addr_to_numeric(const struct in6_addr * );
extern const char *xtables_ip6addr_to_anyname(const struct in6_addr * );
extern const char *xtables_ip6mask_to_numeric(const struct in6_addr * );
extern void xtables_ip6parse_any(const char *, struct in6_addr **,
	struct in6_addr *, unsigned int * );
extern void xtables_ip6parse_multiple(const char *, struct in6_addr **,
	struct in6_addr **, unsigned int * );

/**
 * Print the specified value to standard output, quoting dangerous
 * characters if required.
 */
extern void xtables_save_string(const char *value);

#if defined(ALL_INCLUSIVE) || defined(NO_SHARED_LIBS)
#	ifdef _INIT
#		undef _init
#		define _init _INIT
#	endif
	extern void init_extensions(void);
	extern void init_extensions4(void);
	extern void init_extensions6(void);
#else
#	define _init __attribute__((constructor)) _INIT
#endif

extern const struct xtables_pprot xtables_chain_protos[];
extern u_int16_t xtables_parse_protocol(const char *s);

/* xtoptions.c */
extern void xtables_option_metavalidate(const char *,
					const struct xt_option_entry * );
extern struct option *xtables_options_xfrm(struct option *, struct option *,
					   const struct xt_option_entry *,
					   unsigned int * );
extern void xtables_option_parse(struct xt_option_call * );
extern void xtables_option_tpcall(unsigned int, char **, bool,
				  struct xtables_target *, void * );
extern void xtables_option_mpcall(unsigned int, char **, bool,
				  struct xtables_match *, void * );
extern void xtables_option_tfcall(struct xtables_target * );
extern void xtables_option_mfcall(struct xtables_match * );
extern void xtables_options_fcheck(const char *, unsigned int,
				   const struct xt_option_entry * );

extern struct xtables_lmap *xtables_lmap_init(const char * );
extern void xtables_lmap_free(struct xtables_lmap * );
extern int xtables_lmap_name2id(const struct xtables_lmap *, const char * );
extern const char *xtables_lmap_id2name(const struct xtables_lmap *, int);

#ifdef XTABLES_INTERNAL

/* Shipped modules rely on this... */

#	ifndef ARRAY_SIZE
#		define ARRAY_SIZE(x) (sizeof(x) / sizeof( *(x)))
#	endif

extern void _init(void);

*)
implementation

end.

