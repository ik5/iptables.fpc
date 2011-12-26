{
Free Pascal binding for libip4tc

Copyright (c) 2011 Ido Kanner (idokan at@at gmail dot.dot com)

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.


Documentation arrived from the following web-site:
  http://opalsoft.net/qos/libiptc/qfunction.html
  http://opalsoft.net/qos/libiptc/mfunction.html

IP_TABLES - symbole is to use the header instead of inline code ...
X_TABLES  - symboles for some netfilter headers ...
}
{$IFNDEF LINUX}
  {$ERROR This unit can work only with Linux - It requires iptables that are part of the Linux kernel}
{$ENDIF}
unit libip4tc;

{$mode fpc}{$packrecords c}

interface

uses
  ctypes
  {$IFDEF IP_TABLES}
    , ip_tables
  {$ELSE}
    , Sockets
  {$ENDIF}
  {$IFDEF X_TABLES}
    , x_tables
  {$ENDIF}
  ;

const
  IPTC_LIBRARY = 'libip4tc';

type
  piptc_handle = ^iptc_handle;
  iptc_handle  = record end;
  tiptc_handle = iptc_handle;

  ipt_chainlabel  = array[0..31] of char;
  tipt_chainlabel = ipt_chainlabel;

{$IFNDEF X_TABLES}
type
  xt_counters = record
    // Packet and byte counters
    pcnt, bcnt : cuint64;
  end;
{$ENDIF}

{$IFNDEF IP_TABLES}
const
  IFNAMSIZ = 16;

type
  pipt_ip = ^ipt_ip;
  ipt_ip  = record
    // Source and Destition IP addr
    src,   dst    : in_addr;
    // Mask for src and dest IP addr
    smask, dmask  : in_addr;
    iniface,
    outiface      : array[0..IFNAMSIZ-1] of Char;
    iniface_mask,
    outiface_mask : array[0..IFNAMSIZ-1] of Char;
	  // Protocol, 0 = ANY
    proto         : cuint16;
	  // Flags word
    flags         : cuint8;
    // Inverse flags
    invflags      : cuint8;
  end;
  tipt_ip = ipt_ip;

  pipt_counters = ^ipt_counters;
  ipt_counters  = xt_counters;
  tipt_counters = ipt_counters;

{ This structure defines each of the firewall rules.  Consists of 3
  parts which are 1) general IP header stuff 2) match specific
  stuff 3) the target to perform if the rule matches }

  pipt_entry = ^ipt_entry;
  ipt_entry  = record
    ip            : ipt_ip;
    // Mark with fields that we care about.
    nfcache       : cuint;
    // Size of ipt_entry + matches
    target_offset : cuint16;
    // Size of ipt_entry + matches + target
    next_offset   : cuint16;
    // Back pointer
    comefrom      : cuint;
    // Packet and byte counters.
    counters      : xt_counters;
    // The matches (if any), then the target.
    elems         : array[0..0] of Char;
  end;
  tipt_entry = ipt_entry;

{$ENDIF}

const
  IPTC_LABEL_ACCEPT = 'ACCEPT';
  IPTC_LABEL_DROP   = 'DROP';
  IPTC_LABEL_QUEUE  = 'QUEUE';
  IPTC_LABEL_RETURN = 'RETURN';

{
* Usage:
   Check if a chain exists.

* Description:
   This function checks to see if the chain described in the parameter chain exists in the table.

* Parameters:
   - chain is a char pointer containing the name of the chain we want to check to.
   - handle is a pointer to a structure of type iptc_handle_t that was obtained by a previous call to iptc_init.

* Returns:
   - integer value 1 (true) if the chain exists;
   - integer value 0 (false) if the chain does not exist.
}
function iptc_is_chain(chain : PChar; handle : piptc_handle) : cint;
 cdecl; external IPTC_LIBRARY;

{
* Usage:
   Takes a snapshot of the rules.

* Description:
   This function must be called as initiator before any other function can be called.

* Parameters:
   - tablename is the name of the table we need to query and/or modify; this could be filter, mangle, nat, etc.

* Returns:
   Pointer to a structure of type iptc_handle_t that must be used as main parameter for the rest of functions we will call from libiptc.
   iptc_init returns the pointer to the structure or NULL if it fails.
   If this happens you can invoke iptc_strerror to get information about the error.
}
function iptc_init(tablename : PChar) : piptc_handle;
 cdecl; external IPTC_LIBRARY;

{
* Usage:
   Free snapshot that was taken by iptc_init

* Description:
   This procedure must be called to free a snapshot that was initialized by iptc_init, when the usage is completed.

* Parameters:
   - h is the pointer for the given snapshot.
}
procedure iptc_free(h : piptc_handle);
 cdecl; external IPTC_LIBRARY;

{
* Usage:
   Iterator functions to run through the chains.

* Description:
   This function returns the first chain name in the table.

* Parameters:
   - Pointer to a structure of type iptc_handle that was obtained by a previous call to iptc_init.

* Returns:
   Char pointer to the name of the chain.
}
function iptc_first_chain(handle : piptc_handle) : PChar;
 cdecl; external IPTC_LIBRARY;

{
* Usage:
   Iterator functions to run through the chains.

* Description:
   This function returns the next chain name in the table; NULL means no more chains.

* Parameters:
   - Pointer to a structure of type iptc_handle_t that was obtained by a previous call to iptc_init.

* Returns:
   Char pointer to the name of the chain.
}
function iptc_next_chain(handle : piptc_handle) : PChar;
 cdecl; external IPTC_LIBRARY;

{
* Usage:
   Get first rule in the given chain.

* Description:
   This function returns a pointer to the first rule in the given chain name; NULL for an empty chain.

* Parameters:
   - chain is a char pointer containing the name of the chain we want to get the rules to.
   - handle is a pointer to a structure of type iptc_handle_t that was obtained by a previous call to iptc_init.

* Returns:
   Returns a pointer to an ipt_entry structure containing information about the first rule of the chain.
}
function iptc_first_rule(chain : PChar; handle : piptc_handle) : pipt_entry;
 cdecl; external IPTC_LIBRARY;

{
* Usage:
   Get the next rule in the given chain.

* Description:
   This function returns a pointer to the next rule in the given chain name; NULL means the end of the chain.

* Parameters:
   - prev is a pointer to a structure of type ipt_entry that must be obtained first by a previous call to the function iptc_first_rule.
     In order to get the second and subsequent rules you have to pass a pointer to the structure containing the information about the previous
     rule of the chain.
   - handle is a pointer to a structure of type iptc_handle_t that was obtained by a previous call to iptc_init.

* Returns:
   Returns a pointer to an ipt_entry structure containing information about the next rule of the chain.
}
function iptc_next_rule (prev : pipt_entry; handle : piptc_handle) : pipt_entry;
 cdecl; external IPTC_LIBRARY;

{
* Usage:
   Get a pointer to the target name of this entry.

* Description:
   This function gets the target of the given rule. If it is an extended target, the name of that target is returned.
   If it is a jump to another chain, the name of that chain is returned. If it is a verdict (eg. DROP), that name is returned.
   If it has no target (an accounting-style rule), then the empty string is returned.
   Note that this function should be used instead of using the value of the verdict field of the ipt_entry structure directly,
   as it offers the above further interpretations of the standard verdict.

* Parameters:
   - e is a pointer to a structure of type ipt_entry that must be obtained first by a previous call to the function iptc_first_rule
     or the function iptc_next_rule.
   - handle is a pointer to a structure of type iptc_handle_t that was obtained by a previous call to iptc_init.

* Returns:
   Returns a char pointer to the target name. See Description above for more information.
}
function iptc_get_target(e : pipt_entry; handle : piptc_handle) : PChar;
 cdecl; external IPTC_LIBRARY;

{
* Usage:
   Is this a built-in chain?

* Description:
    This function is used to check if a given chain name is a built-in chain or not.

* Parameters:
   - chain is a char pointer containing the name of the chain we want to check to.
   - handle is a pointer to a structure of type iptc_handle_t that was obtained by a previous call to iptc_init.

* Returns:
   - Returns integer value 1 (true) if the given chain name is the name of a builtin chain;
   - returns integer value 0 (false) is not.
}
function iptc_builtin(chain : PChar; handle : piptc_handle) : cint;
 cdecl; external IPTC_LIBRARY;

{
* Usage:
   Get the policy of a given built-in chain.

* Description:
   This function gets the policy of a built-in chain, and fills in the counters argument with the hit statistics on that policy.

* Parameters:
   - chain is the built-in chain you want to get the policy to.
   - counter is a pointer to an ipt_counters structure to be filled by the function
   - handle is a pointer to a structure of type iptc_handle_t structure identifying the table we are working to that was obtained
     by a previous call to iptc_init.

* Returns:
   Returns a char pointer to the policy name.
}
function iptc_get_policy(chain   : PChar;
                         counter : pipt_counters;
                         handle : piptc_handle)   : PChar;
 cdecl; external IPTC_LIBRARY;

////////////////////////////////////////////////////////////////////////////////

{
* Usage:
   Insert a new rule in a chain.

* Description:
   This function insert a rule defined in structure type ipt_entry in chain chain into position defined by integer value rulenum.
   Rule numbers start at 1 for the first rule.

* Parameters:
   - chain is a char pointer to the name of the chain to be modified;
   - e is a pointer to a structure of type ipt_entry that contains information about the rule to be inserted.
     The programmer must fill the fields of this structure with values required to define his or her rule before
     passing the pointer as parameter to the function.
   - rulenum is an integer value defined the position in the chain of rules where the new rule will be inserted.
     Rule numbers start at 1 for the first rule.
   - handle is a pointer to a structure of type iptc_handle_t that was obtained by a previous call to iptc_init.

* Returns:
   - Returns integer value 1 (true) if successful;
   - returns integer value 0 (false) if fails. In this case errno is set to the error number generated.

   Use iptc_strerror to get a meaningful information about the problem.
   If errno = 0, it means there was a version error (ie. upgrade libiptc).
}
function iptc_insert_entry(chain   : ipt_chainlabel;
                           e       : pipt_entry;
                           rulenum : cuint;
                           handle  : piptc_handle)    : cint;
 cdecl; external IPTC_LIBRARY;

{
* Usage:
   Replace an old rule in a chain with a new one.

* Description:
   This function replace the entry rule in chain chain positioned at rulenum with the rule defined in structure type ipt_entry.
   Rule numbers start at 1 for the first rule.

* Parameters:
   - chain is a char pointer to the name of the chain to be modified;
   - e is a pointer to a structure of type ipt_entry that contains information about the rule to be inserted.
     The programmer must fill the fields of this structure with values required to define his or her rule before
     passing the pointer as parameter to the function.
   - rulenum is an integer value defined the position in the chain of rules where the old rule will be replaced by the new one.
     Rule numbers start at 1 for the first rule.
   - handle is a pointer to a structure of type iptc_handle_t that was obtained by a previous call to iptc_init.

* Returns:
   - Returns integer value 1 (true) if successful;
   - returns integer value 0 (false) if fails. In this case errno is set to the error number generated.

   Use iptc_strerror to get a meaningful information about the problem.
   If errno = 0, it means there was a version error (ie. upgrade libiptc).
}
function iptc_replace_entry(chain   : ipt_chainlabel;
                            e       : pipt_entry;
                            rulenum : cuint;
                            handle  : piptc_handle)  : cint;
 cdecl; external IPTC_LIBRARY;

{
* Usage:
   Append a new rule in a chain.

* Description:
   This function append a rule defined in structure type ipt_entry in chain chain (equivalent to insert with rulenum = length of chain).

* Parameters:
   - chain is a char pointer to the name of the chain to be modified;
   - e is a pointer to a structure of type ipt_entry that contains information about the rule to be appended.
     The programmer must fill the fields of this structure with values required to define his or her rule before
     passing the pointer as parameter to the function.
   - handle is a pointer to a structure of type iptc_handle_t that was obtained by a previous call to iptc_init.

* Returns:
   - Returns integer value 1 (true) if successful;
   - returns integer value 0 (false) if fails. In this case errno is set to the error number generated.

   Use iptc_strerror to get a meaningful information about the problem.
   If errno = 0, it means there was a version error (ie. upgrade libiptc).
}
function iptc_append_entry(chain  : ipt_chainlabel;
                           e      : pipt_entry;
                           handle : piptc_handle)   : cint;
 cdecl; external IPTC_LIBRARY;

{
* Usage:
   Check whether a matching rule exists

* Description:
   This function check whether a matching rule based on pointer to ipt_entry exists in the chain.

* Parameters:
   - chain is a char pointer to the name of the chain to be compared to;
   - origfw is a pointer for ipt_entry
   - matchmask is a char pointer
   - handle is a pointer to a structure of type iptc_handle_t that was obtained by a previous call to iptc_init.

* Returns:
   - Returns integer value
}
function iptc_check_entry(chain     : ipt_chainlabel;
                          origfw    : pipt_entry;
                          matchmask : PChar;
                          handle    : piptc_handle)   : cint;
 cdecl; external IPTC_LIBRARY;

{
* Usage:
   Delete the first rule in `chain' which matches `e', subject to matchmask (array of length == origfw)

* Description:
   Delete the first rule in `chain' which matches `e', subject to matchmask (array of length == origfw)

* Parameters:
   - chain is a char pointer to the name of the chain to be compared to;
   - origfw is a pointer for ipt_entry
   - matchmask is a char pointer
   - handle is a pointer to a structure of type iptc_handle_t that was obtained by a previous call to iptc_init.

* Returns:
   - Returns integer value
}
function iptc_delete_entry(chain     : ipt_chainlabel;
                           matchmask : PChar;
                           handle    : piptc_handle)    : cint;
 cdecl; external IPTC_LIBRARY;

{
* Usage:
   Delete a rule in a chain.

* Description:
   This function delete the entry rule in chain chain positioned at rulenum. Rule numbers start at 1 for the first rule.

* Parameters:
   - chain is a char pointer to the name of the chain to be modified;
   - rulenum is an integer value defined the position in the chain of rules where the rule will be deleted.
   - handle is a pointer to a structure of type iptc_handle_t that was obtained by a previous call to iptc_init.

* Returns:
   - Returns integer value 1 (true) if successful;
   - returns integer value 0 (false) if fails. In this case errno is set to the error number generated.

   Use iptc_strerror to get a meaningful information about the problem.
   If errno = 0, it means there was a version error (ie. upgrade libiptc).
}
function iptc_delete_num_entry(chain   : ipt_chainlabel;
                               rulenum : cuint;
                               handle  : piptc_handle)   : cint;
 cdecl; external IPTC_LIBRARY;

{
* Usage:
   Check the packet `e' on chain `chain'.  Returns the verdict, or NULL and sets errno.

* Description:
   Check the packet `e' on chain `chain'.  Returns the verdict, or NULL and sets errno.

* Parameters:
   - chain is a char pointer to the name of the chain to be checked.
   - entry is a pointer to a structure of type ipt_entry that contains information about the rule to be chcked
     The programmer must fill the fields of this structure with values required to define his or her rule before
     passing the pointer as parameter to the function.
   - handle is a pointer to a structure of type iptc_handle_t that was obtained by a previous call to iptc_init.

* Returns:
   Return the verdict of the check or null with errno set.
}
function iptc_check_packet(chain  : ipt_chainlabel;
                           entry  : pipt_entry;
                           handle : piptc_handle)   : PChar;
 cdecl; external IPTC_LIBRARY;

{
* Usage:
   Empty a chain.

* Description:
   This function flushes the rule entries in the given chain (ie. empties chain).

* Parameters:
   - chain is a char pointer to the name of the chain to be flushed;
   - handle is a pointer to a structure of type iptc_handle_t that was obtained by a previous call to iptc_init.

* Returns:
   - Returns integer value 1 (true) if successful;
   - returns integer value 0 (false) if fails. In this case errno is set to the error number generated.

   Use iptc_strerror to get a meaningful information about the problem.
   If errno = 0, it means there was a version error (ie. upgrade libiptc).
}
function iptc_flush_entries(chain : ipt_chainlabel; handle : piptc_handle) : cint;
 cdecl; external IPTC_LIBRARY;

{
* Usage:
   Zeroes the chain counters.

* Description:
   This function zeroes the counters in the given chain.

* Parameters:
   - chain is a char pointer to the name of the chain which counters will be zero;
   - handle is a pointer to a structure of type iptc_handle_t that was obtained by a previous call to iptc_init.

* Returns:
   - Returns integer value 1 (true) if successful;
   - returns integer value 0 (false) if fails. In this case errno is set to the error number generated.

   Use iptc_strerror to get a meaningful information about the problem.
   If errno = 0, it means there was a version error (ie. upgrade libiptc).
}
function iptc_zero_entries(chain : ipt_chainlabel; handle : piptc_handle) : cint;
 cdecl; external IPTC_LIBRARY;

{
* Usage:
   Create a new chain.

* Description:
   This function create a new chain in the table.

* Parameters:
   - chain is a char pointer to the name of the chain to be created;
   - handle is a pointer to a structure of type iptc_handle_t that was obtained by a previous call to iptc_init.

* Returns:
   - Returns integer value 1 (true) if successful;
   - returns integer value 0 (false) if fails. In this case errno is set to the error number generated.

   Use iptc_strerror to get a meaningful information about the problem.
   If errno = 0, it means there was a version error (ie. upgrade libiptc).
}
function iptc_create_chain(chain : ipt_chainlabel; handle : piptc_handle) : cint;
 cdecl; external IPTC_LIBRARY;

{
* Usage:
   Delete a chain.

* Description:
   This function delete the chain identified by the char pointer chain in the table.

* Parameters:
   - chain is a char pointer to the name of the chain to be deleted;
   - handle is a pointer to a structure of type iptc_handle_t that was obtained by a previous call to iptc_init.

* Returns:
   - Returns integer value 1 (true) if successful;
   - returns integer value 0 (false) if fails. In this case errno is set to the error number generated.

   Use iptc_strerror to get a meaningful information about the problem.
   If errno = 0, it means there was a version error (ie. upgrade libiptc)
}
function iptc_delete_chain(chain : ipt_chainlabel; handle : piptc_handle) : cint;
 cdecl; external IPTC_LIBRARY;

{
* Usage:
   Rename a chain.

* Description:
   This function rename the chain identified by the char pointer oldname to a new name newname in the table.

* Parameters:
   - oldname is a char pointer to the name of the chain to be renamed
   - newname is the new name;
   - handle is a pointer to a structure of type iptc_handle_t that was obtained by a previous call to iptc_init.

* Returns:
   - Returns integer value 1 (true) if successful;
   - returns integer value 0 (false) if fails. In this case errno is set to the error number generated.

   Use iptc_strerror to get a meaningful information about the problem.
   If errno = 0, it means there was a version error (ie. upgrade libiptc).
}
function iptc_rename_chain(oldname, newname : ipt_chainlabel;
                           handle           : piptc_handle)  : cint;
 cdecl; external IPTC_LIBRARY;

{
* Usage:
   Set the policy in a built-in chain.

* Description:
   This function set the policy in chain chain to the value represented by the char pointer policy.
   If you want to set at the same time the counters of the chain, fill those values in a structure of
   type ipt_counters and pass a pointer to it as parameter counters.
   Be careful: the chain must be a built-in chain.

* Parameters:
   - chain is a char pointer to the name of the chain to be modified;
   - policy is a char pointer to the name of the policy to be set.
   - counters is a pointer to an ipt_counters structure to be used to set the counters of the chain.
   - handle is a pointer to a structure of type iptc_handle_t that was obtained by a previous call to iptc_init.

* Returns:
   - Returns integer value 1 (true) if successful;
   - returns integer value 0 (false) if fails. In this case errno is set to the error number generated.

   Use iptc_strerror to get a meaningful information about the problem.
   If errno = 0, it means there was a version error (ie. upgrade libiptc).
}
function iptc_set_policy(chain, policy : ipt_chainlabel;
                         counters      : pipt_counters;
                         handle        : piptc_handle)  : cint;
 cdecl; external IPTC_LIBRARY;

{
  Get the number of refrences to this chain
}
function iptc_get_references(ref    : pcuint;
                             chain  : ipt_chainlabel;
                             handle : piptc_handle)    : cint;
 cdecl; external IPTC_LIBRARY;

{
* Usage:
   Read counters of a rule in a chain.

* Description:
   This function read and returns packet and byte counters of the entry rule in chain chain positioned at rulenum.
   Counters are returned in a pointer to a type structure ipt_counters. Rule numbers start at 1 for the first rule.

* Parameters:
   - chain is a char pointer to the name of the chain to be readed;
   - rulenum is an integer value defined the position in the chain of rules of the rule which counters will be read.
   - handle is a pointer to a structure of type iptc_handle_t that was obtained by a previous call to iptc_init.

* Returns:
   Returns a pointer to an ipt_counters structure containing the byte and packet counters readed.
}
function iptc_read_counter(chain   : ipt_chainlabel;
                           rulenum : cuint;
                           handle  : piptc_handle)    : pipt_counters;
 cdecl; external IPTC_LIBRARY;

{
* Usage:
   Zero counters of a rule in a chain.

* Description:
   This function zero packet and byte counters of the entry rule in chain chain positioned at rulenum.
   Rule numbers start at 1 for the first rule.

* Parameters:
   - chain is a char pointer to the name of the chain to be modified;
   - rulenum is an integer value defined the position in the chain of rules of the rule which counters will be zero.
   - handle is a pointer to a structure of type iptc_handle_t that was obtained by a previous call to iptc_init.

* Returns:
   - Returns integer value 1 (true) if successful;
   - returns integer value 0 (false) if fails. In this case errno is set to the error number generated.

   Use iptc_strerror to get a meaningful information about the problem.
   If errno = 0, it means there was a version error (ie. upgrade libiptc).
}
function iptc_zero_counter(chain   : ipt_chainlabel;
                           rulenum : cuint;
                           handle  : piptc_handle)   : cint;
 cdecl; external IPTC_LIBRARY;

{
* Usage:
   Set counters of a rule in a chain.

* Description:
   This function set packet and byte counters of the entry rule in chain chain positioned at rulenum with
   values passed in a type structure ipt_counters. Rule numbers start at 1 for the first rule.

* Parameters:
   - chain is a char pointer to the name of the chain to be modified;
   - rulenum is an integer value defined the position in the chain of rules of the rule which counters will be set.
   - counters is a pointer to an ipt_counters structure to be used to set the counters of the rule;
     the programmer must fill the fields of this structure with values to be set.
   - handle is a pointer to a structure of type iptc_handle_t that was obtained by a previous call to iptc_init.

* Returns:
   - Returns integer value 1 (true) if successful;
   - returns integer value 0 (false) if fails. In this case errno is set to the error number generated.

   Use iptc_strerror to get a meaningful information about the problem.
   If errno = 0, it means there was a version error (ie. upgrade libiptc).
}
function iptc_set_counter(chain    : ipt_chainlabel;
                          rulenum  : cuint;
                          counters : pipt_counters;
                          handle   : piptc_handle)   : cint;
 cdecl; external IPTC_LIBRARY;

{
* Usage:
   Makes the actual changes.

* Description:
   The tables that you change are not written back until the iptc_commit() function is called.
   This means it is possible for two library users operating on the same chain to race each other;
   locking would be required to prevent this, and it is not currently done.
   There is no race with counters, however; counters are added back in to the kernel in such a way that counter
   increments between the reading and writing of the table still show up in the new table.
   To protect the status of the system you must commit your changes.

* Parameters:
   - handle is a pointer to a structure of type iptc_handle_t that was obtained by a previous call to iptc_init.

* Returns:
   - Returns integer value 1 (true) if successful;
   - returns integer value 0 (false) if fails. In this case errno is set to the error number generated.

   Use iptc_strerror to get a meaningful information about the problem.
   If errno = 0, it means there was a version error (ie. upgrade libiptc).
}
function iptc_commit(handle : piptc_handle) : cint;
 cdecl; external IPTC_LIBRARY;

{
 Get raw socket.
}
function iptc_get_raw_socket : cint;
 cdecl; external IPTC_LIBRARY;

{
* Usage:
   Translates error numbers into more human-readable form.

* Description:
   This function returns a more meaningful explanation of a failure code in the iptc library.
   If a function fails, it will always set errno. This value can be passed to iptc_strerror() to yield an error message.

* Parameters:
   - err is an integer indicating the error number.

* Returns:
   Char pointer containing the error description.
}
function iptc_strerror(err : cint) : PChar;
 cdecl; external IPTC_LIBRARY;

{
  print connection information on screen
}
procedure dump_entries(handle : piptc_handle);
 cdecl; external IPTC_LIBRARY;

implementation

end.

