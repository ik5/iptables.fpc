<c/>/* netsim.c   29 Mar 2006
 
   This code is released under GPL
   You can modify it and do anything with it, as long as it is released under GPL.
 
   A note for people interested in learning how to use libipq: Read this mini 
   documentation before trying to understand the code!
   * To understand the code, make sure you have the man page of libipq nearby and 
     start reading from the beginning of the main() function; This is because not 
     all functions in this file is relevant to libipq. Follow the comments and you 
     should be fine.
   * This project doesn't use features higher than layer 3 (IP), so I won't look 
     into the TCP/UDP header (although it's possible). 
 
   Check out this link to see another example that does this: 
   http://www.crhc.uiuc.edu/~grier/projects/libipq.html
 
   Here is a copy of the man page: http://www.cs.princeton.edu/~nakao/libipq.htm
 
   Authors: Dumitrascu Irina (dumitrascu.irina@gmail.com)
                 Adrian Popa (adrian.popa.gh@gmail.com)
 
   Version: 0.1
 
   Purpose: A network simulator (delays, errors, duplicates, reorders and drops 
            packets that are sent to it)
 
   How to compile: gcc -o netsim netsim.c -lipq  (requires libipq-dev)
 
   How to run: 
      -consider the following network topology:
 
      |Host A|----------------------|Router|------------------------|Host B|
           .2                    .1          .1                     .2
                  10.0.0.0/24                  192.168.0.0/24
 
      First, set an iptables rule that will send certain packets to IPQ (you 
      need iptable_filter and ip_queue modules loaded): 
 
        Router# echo "1" >/proc/sys/net/ipv4/ip_forward      
                # start routing
        Router# iptables -A FORWARD -p icmp --icmp-type echo-request -j QUEUE  
                # send all icmp echo requests to IPQ
 
      Start netsim with the option(s) you want:
 
        Router#./netsim --delay min=0,max=10,percent=30
 
      Start a ping from Host A: 
 
        HostA# ping 192.168.0.2
 
      (if you get a Network Unreachable error, make sure that you have a default 
      gateway or route information about 192.168 set)
      You should see the results on the ping output and on the Router's screen.
 
   Common errors/troubleshooting:
      Command:
            Router$ ./netsim --drop percent=22
            Received an error message: 1
      Answer: netsim must run with root privileges
 
      Command:
            Router# ./netsim --drop percent=22
            Failed to send netlink message: Connection refused
      Answer: you need to load the ip_queue module (modprobe ip_queue) or set an
              iptables -j QUEUE rule
 
      Command:
            Router# ./netsim --drop percent=22
            Failed to create netlink socket
      Answer: you can't run two instances of netsim at the same time on the same 
              machine. Kill one of them.
 
   Known bugs/errors/limitations:
      - can't create new packets (libipq limitation), so the duplication is done by 
        copying the content of packet i to packet i+1 (and losing the original 
        content of packet i+1)
      - if there are multiple iptables -j QUEUE rules active, it's possible to have 
        an unpredictible output for --reorder and --duplicate (can be fixed if you 
        check to see that all packets that are to be reordered or duplicated come 
        from the same iptables rule)
      - if you modify a packet and want it to go through, you MUST recalculate its 
        CRC sum. Otherwise it MIGHT be dropped by the kernel, and will surely be 
        dropped at the destination. 
      - the percentages set in the command line are not always respected; they are 
        respected only for a very large number of packets.
      - in the case of excessive delays set by the delay parameter, you might 
        experience packet drops because the packet queue can fill up.
      - by default, iptables drops all packets that match a -j QUEUE rule if no ipq 
        listener is registered (netsim isn't started)
 
   Disclaimer: This program can be DANGEROUS, so make sure that you know what you 
               are doing before using it on a network. It was intended only as an 
               exercise; it shouldn't be used in real life! You were warned... 
               (If you notice network problems after you start netsim, kill it and 
               issue an 'iptables -F' to delete all the rules)
*/
 
#include <linux/netfilter.h>  // constants 
#include <linux/ip.h>         // ip header
#include <libipq/libipq.h>    // libipq API
#include <stdio.h>            // general definitions
#include <stdlib.h>           // for exit()
#include <string.h>           // for command line parsing
#include <time.h>             // for srand()
#include <unistd.h>           // for usleep()
#include <signal.h>           // for signal() (ctrl+c)
 
#define BUFFERSIZE 2048
 
void showUsage();
int parseCmdline(int argc, char **argv);
void showCmdline();
int validateCmdline();
void exitWithError(struct ipq_handle *h);
 
/* A structure holding different variables set based on the command line parameters.
 */
struct {
   unsigned short int delay;
   unsigned int delay_min;
   unsigned int delay_max;
   unsigned short int delay_percent;
   unsigned short int drop;
   unsigned short int drop_percent;
   unsigned short int reorder;
   unsigned short int reorder_percent;
   unsigned int reorder_max;
   unsigned short int duplicate;
   unsigned short int duplicate_percent;
   unsigned short int error;
   unsigned short int error_percent;
   unsigned short int mangle;
   unsigned short int mangle_percent;
} cmdline;
 
/* Global variables - for statistics
 */
int total_packets=0, \
      delayed_packets=0, \
      dropped_packets=0, \
      duplicated_packets=0, \
      errored_packets=0, \
      reordered_packets=0, \
      mangled_packets=0;
 
/* Method to parse the command line -> takes argc and argv from main and writes 
 * flags in the structure cmdline. (This is NOT the most efficient way to do this, but hey...)
 * Returns 0 for success and anything else for failiure.
 */
int parseCmdline(int argc, char **argv){
   int i=0;
   for ( i = 1; i < argc; i++)
    {
       if(strstr(argv[i],"--delay")!=NULL){ // we found the delay parameter
          cmdline.delay=1;                  // set to do delay
          // the next parameters should contain min,max and percent
          if((i+1)==argc) return 1;         // no more arguments
          char* min=strstr(argv[i+1], "min");
          char* max=strstr(argv[i+1], "max");
          char* percent=strstr(argv[i+1], "percent");
          if(min!=NULL && max!=NULL && percent!=NULL){
             // everything is as expected
             char* temp=min;                // get the first parameter
             temp = strchr(temp, '=');      // extract from '=' to the end
             temp = strtok(temp, ",");      // cut the first comma
             temp = temp +1;                // cut the equal from the result
             cmdline.delay_min=atoi(temp);
             // now, for the second parameter
             temp = max;
             temp = strchr(temp, '=');      // extract from '=' to the end
             temp = strtok(temp, ",");      // cut the first comma
             temp = temp +1;                // cut the equal from the result
             cmdline.delay_max=atoi(temp);
             // the last parameter
             temp = percent;
             temp = strchr(temp, '=');      // extract from '=' to the end
             temp = temp +1;                // cut the equal from the result
             cmdline.delay_percent=atoi(temp);
             i++;                           // skip a parameter, because it has been parsed
          } // from all the NULL's
          else return 1;
          continue;                         // start over
       } // from --delay
 
       if(strstr(argv[i],"--drop")!=NULL){  // we found the --drop parameter
          cmdline.drop=1;                   // set to do drop
          if((i+1)==argc) return 1;         // no more parameters
          char* percent=strstr(argv[i+1], "percent");
          if(percent!=NULL){
             percent=strchr(percent, '=');  // extract from '=' to the end
             percent=percent+1;             // cut the equal from the result
             cmdline.drop_percent=atoi(percent);
             i++;                           // skip a parameter because it has been parsed
          } // from if
          else return 1;
          continue;
       } // from --drop
 
       if(strstr(argv[i],"--duplicate")!=NULL){ // we found --duplicate
          cmdline.duplicate=1;              // set to do duplicate
          if((i+1)==argc) return 1;         // no more parameters
          char* percent=strstr(argv[i+1], "percent");
          if(percent!=NULL){
             percent=strchr(percent, '=');  // extract from '=' to the end
             percent=percent+1;             // cut the equal from the result
             cmdline.duplicate_percent=atoi(percent);
             i++;                           // skip a parameter because it has been parsed already
          } // from if
          else return 1;
          continue;
       } // from --duplicate
 
       if(strstr(argv[i],"--error")!=NULL){ //we found --error
          cmdline.error=1;                  // set to do some error (as if internal bugs weren't enough! :)
          if((i+1)==argc) return 1;         // no more parameters
          char* percent=strstr(argv[i+1], "percent");
          if(percent!=NULL){
             percent=strchr(percent, '=');  // extract from '=' to the end
             percent=percent+1;             // cut the equal from the result
             cmdline.error_percent=atoi(percent);
             i++;                           // skip a parameter because it has been parsed
          } // from if
          else return 1;
          continue;
       } // from --error
 
       if(strstr(argv[i],"--mangle")!=NULL){ // we found mangle
          cmdline.mangle=1;                 // set to do mangle
          if((i+1)==argc) return 1;         //no more parameters
          char* percent=strstr(argv[i+1], "percent");
          if(percent!=NULL){
             percent=strchr(percent, '=');  // extract from '=' to the end
             percent=percent+1;             // cut the equal from the result
             cmdline.mangle_percent=atoi(percent);
             i++;                           // skip a parameter because it has been parsed already
          } // from if
          else return 1;
          continue;
       } // from --mangle
 
       if(strstr(argv[i],"--reorder")!=NULL){ // we found reorder
          cmdline.reorder=1;                // set to do reordering
          if((i+1)==argc) return 1;         // no more parameters
          char* percent=strstr(argv[i+1], "percent");
          char* max=strstr(argv[i+1], "max");
          if(percent!=NULL && max!=NULL){
             char *temp = percent;
             temp=strchr(temp, '=');        // extract from '=' to the end of the string
             temp=strtok(temp, ",");        // cut what's after the comma
             temp=temp+1;                   // cut the equal from the result
             cmdline.reorder_percent=atoi(temp);
             temp=max;
             temp=strchr(temp, '=');        // extract from '=' to the end
             temp=temp+1;                   // cut the equal from the result
             cmdline.reorder_max=atoi(temp);
             i++;                           // skip a parameter because it has been parsed
          } // from if
          else return 1;
          continue;
       } // from --reorder
    }
    return 0;
}
 
 
/* Debug method, used to test if parameter parsing works as expected.
 */
void showCmdline(){
   fprintf(stderr, "\nDEBUG: cmdline.delay=%d",cmdline.delay);
   fprintf(stderr, "\nDEBUG: cmdline.delay_min=%d",cmdline.delay_min);
   fprintf(stderr, "\nDEBUG: cmdline.delay_max=%d",cmdline.delay_max);
   fprintf(stderr, "\nDEBUG: cmdline.delay_percent=%d",cmdline.delay_percent);
   fprintf(stderr, "\nDEBUG: cmdline.drop=%d",cmdline.drop);
   fprintf(stderr, "\nDEBUG: cmdline.drop_percent=%d",cmdline.drop_percent);
   fprintf(stderr, "\nDEBUG: cmdline.reorder=%d",cmdline.reorder);
   fprintf(stderr, "\nDEBUG: cmdline.reorder_percent=%d",cmdline.reorder_percent);
   fprintf(stderr, "\nDEBUG: cmdline.reorder_max=%d",cmdline.reorder_max);
   fprintf(stderr, "\nDEBUG: cmdline.duplicate=%d",cmdline.duplicate);
   fprintf(stderr, "\nDEBUG: cmdline.duplicate_percent=%d",cmdline.duplicate_percent);
   fprintf(stderr, "\nDEBUG: cmdline.error=%d",cmdline.error);
   fprintf(stderr, "\nDEBUG: cmdline.error_percent=%d",cmdline.error_percent);
   fprintf(stderr, "\nDEBUG: cmdline.mangle=%d",cmdline.mangle);
   fprintf(stderr, "\nDEBUG: cmdline.mangle_percent=%d",cmdline.mangle_percent);
}
 
 
/* Method that checks that the values in the structure cmdline are relevant 
 * (ex: percent <100)
 * Returns 0 for success and anything else for failiure.
 */
int validateCmdline(){
   if((cmdline.delay_min>cmdline.delay_max) || (cmdline.reorder_max>5) || \
      (cmdline.delay_percent>100) || (cmdline.drop_percent>100) || \
      (cmdline.reorder_percent>100) || (cmdline.duplicate_percent>100) || \
      (cmdline.error_percent>100) || (cmdline.mangle_percent>100) || \
      (cmdline.reorder_max<=0))
      return 1;
   else return 0;
}
 
 
/* Method that displays the usage information (help)
 */
void showUsage(){
   fprintf(stderr, "\nnetsim v0.1\n\nUsage: netsim OPTION...");
   fprintf(stderr, "\nOption list:");
   fprintf(stderr, "\n  --delay\t\t\tdelays some packets");
   fprintf(stderr, "\n      min=TIME\t\t\tminimum delay time in ms");
   fprintf(stderr, "\n      max=TIME\t\t\tmaximum delay time in ms");
   fprintf(stderr, "\n      percent=PERCENT\t\tpercent of packets to be delayed");
   fprintf(stderr, "\n  --drop\t\t\tdrops some packets");
   fprintf(stderr, "\n      percent=PERCENT\t\tpercent of packets to be dropped");
   fprintf(stderr, "\n  --duplicate\t\t\tduplicates some packets");
   fprintf(stderr, "\n      percent=PERCENT\t\tpercent of packets to be duplicated");
   fprintf(stderr, "\n  --error\t\t\tcreates bit errors in some packets");
   fprintf(stderr, "\n      percent=PERCENT\t\tpercent of packets to be errored");
   fprintf(stderr, "\n  --mangle\t\t\tmodifies TOS in ip header");
   fprintf(stderr, "\n      percent=PERCENT\t\tpercent of packets to be mangled");
   fprintf(stderr, "\n  --reorder\t\t\tmodifies order of packets");
   fprintf(stderr, "\n      max=NUMBER\t\tnumber of packets to reorder");
   fprintf(stderr, "\n      percent=PERCENT\t\tpercent of packets to be duplicated");
   fprintf(stderr, "\n\nExamples:");
   fprintf(stderr, "\nnetsim --delay min=12,max=20,percent=5");
   fprintf(stderr, "\nnetsim --drop percent=3");
   fprintf(stderr, "\nnetsim --duplicate percent=3");
   fprintf(stderr, "\nnetsim --delay min=0,max=12,percent=7 --error percent=3 --duplicate percent=2\n");
}
 
 
/* Method used to exit cleanly in case of errors in libipq
 */
void exitWithError(struct ipq_handle *h){
   ipq_perror("Queue Error:");
   ipq_destroy_handle(h);
   exit(2);
}
 
 
/* Dumps the packet in hex on the screen - used for debug
 */
void showPacket(ipq_packet_msg_t *pkt){
   int i=0;
   printf("\n Raw packet: --------------------------\n");
   for(i=0;i<pkt->data_len;i++){
      printf("%x ", pkt->payload[i]);
   }
   printf("\n End of raw packet ------------------");
}
 
/* Checksum for IP header 
 */
unsigned short checksum(unsigned short *addr, int len)
{
   int nleft=len;
   int sum=0;
   unsigned short *w=addr;
   unsigned short answer=0;
 
   while(nleft>1){
      sum+=*w++;
      nleft-=2;
   }
   if(nleft==1){
      *(unsigned char *)(&answer)=*(unsigned char *)w;
      sum+=answer;     
   }
   sum=(sum>>16)+(sum&0xffff);
   sum+=(sum>>16);
   answer=~sum;
   return answer;
}
 
 
/* Method that calculates the percent
 */
int doPercent(int percent){
   if (percent>0)
      return rand()%((int)(100/percent+0.5));
   else
      return 1;
}
 
/* Handler for CTRL+C; Displays some statistics when exiting */
void ctrlC(int sig){
   printf("\nStatistics:");
   printf("\nTotal packets=%d Delayed=%d Dropped=%d\nDuplicated=%d Errored=%d Reordered=%d Mangled=%d\n", \
         total_packets,delayed_packets, dropped_packets, duplicated_packets, 
         errored_packets, reordered_packets, mangled_packets);
   exit(0);
}
 
 
/* ---Verdict methods--- */
/* Can return 0 if the packet is to be accepted without modification, 
 *                   1 if the packet is to be accepted with modification(s),
 *                   2 if the packet is to be dropped.
 
/* Method that decides whether a packet should be errored */
/* Returns 0 if the packet is to be accepted without modification, 
 *              1 if the packet is to be accepted with modification(s),
 */
int doError(struct ipq_handle *h, ipq_packet_msg_t *pkt){
   if(doPercent(cmdline.error_percent)==0){ // if we need to do error
      printf(" erroring ");
      struct iphdr *iph = ((struct iphdr *)pkt->payload); // get the ip header
      iph->tot_len=iph->tot_len+1;          // modify the ip packet length field so 
                                            // that the destination receives a bad CRC
      errored_packets++;
      return 1;                             // send the modified packet (to be forwarded)
   }
  return 0;                                 // nothing to do to this packet
}
 
/* Method that decides whether a packet should be delayed */
/* Returns 0 if the packet is to be accepted without modification, 
 */
int doDelay(struct ipq_handle *h, ipq_packet_msg_t *pkt){
   if(doPercent(cmdline.delay_percent)==0){ // if we need to delay the packet
      printf(" delaying ");
      int ms = rand()%(cmdline.delay_max - cmdline.delay_min); // calculate this delay (randomly)
      ms+=cmdline.delay_min;
      delayed_packets++;
      usleep(ms*1000);                      // sleeping 'ms' miliseconds
   }
   return 0;                                // forward the packet normally
}
 
/* Method that decides whether a packet should be dropped */
/* Returns 0 if the packet is to be accepted without modification, 
 *              2 if the packet is to be dropped.
 */
int doDrop(struct ipq_handle *h, ipq_packet_msg_t *pkt){
   if(doPercent(cmdline.drop_percent)==0){  // if we need to drop this packet
      printf(" dropping ");
      dropped_packets++;
      return 2;                             // notify that it is to be dropped
      }
   return 0;                                // forward normally
}
 
/* Method that decides whether a packet should be reordered */
/* Returns 0 if the packet is to be accepted without modification, 
 *              1 if the packet is to be accepted with modification(s),
 */
int doReorder(struct ipq_handle *h, ipq_packet_msg_t *pkt){
   if(doPercent(cmdline.reorder_percent)==0){ // if this packet needs to be reordered
      printf(" reordering ");
 
      /* Here it gets really tricky. To reorder, one must receive all packets and
         send them again in the reverse order. This is just what we do. Note that 
         your packets will be delayed (because we're waiting for cmdline.reorder_max
         packets to arrive first)*/
 
      ipq_packet_msg_t *packets[]={ NULL, NULL, NULL, NULL, NULL }; // an array to hold 5 packets (maximum).
      unsigned char buffer[5][BUFFERSIZE];  // local buffer
      int status=0, i=0;
 
      packets[0]=pkt;                       // copy the current (previously obtained) packet 
                                            // to packets[0]; This will be the last to leave
      reordered_packets++;
      printf(".");                          // display a '.' for every packet sent from now on
      for(i=1; i<cmdline.reorder_max;i++){
                                            // read the next packet
         status = ipq_read(h, buffer[i], BUFFERSIZE, 0); // handle h, destination_buffer, buffer_size, timeout
         if (status<0)
            exitWithError(h);
 
                                            // determine the message type -> Packet or error message
         if(ipq_message_type(buffer[i])==NLMSG_ERROR){
            fprintf(stderr, "Received an error message in doReorder(): %d", 
                    ipq_get_msgerr(buffer[i])); // display the error.
         }
         if(ipq_message_type(buffer[i])==IPQM_PACKET){
                                            // we received an actual packet of data.
            pkt=ipq_get_packet(buffer[i]);  // write the actual packet in pkt   
            total_packets++;
            reordered_packets++;
            packets[i]=pkt;                 // store this packet into the array, where it will be read later
            printf(".");
         }
      }
 
                                            // do the reordering and set verdicts
      for(i=cmdline.reorder_max-1; i>0; i--){ // go backwards
         pkt=packets[i];
         status=ipq_set_verdict(h, pkt->packet_id, NF_ACCEPT, pkt->data_len, pkt->payload); 
                                            // set the verdict for each 
                                            //packet, until we get to the last one
      }
 
      pkt=packets[0];                       // let the main program set the verdict for the first packet.
      return 1;                             // forward the modified packet (it was copied from packets[0])
   }
   return 0;                                // no reordering, nothing special to do
}
 
/* Method that decides whether a packet should be duplicated */
/* Returns 0 if the packet is to be accepted without modification, 
 *              1 if the packet is to be accepted with modification(s),
 */
int doDuplicate(struct ipq_handle *h, ipq_packet_msg_t *pkt){
   if(doPercent(cmdline.duplicate_percent)==0){ // if we must duplicate this packet
      printf(" duplicating ");
 
      int status = 0;
 
      /* There's a catch about outputting new packets using libipq. Normally, libipq 
         can't create new packets (that weren't captured by the iptables filter. So, 
         in order to do duplication, we have to discard the next packet that arrives 
         and overwrite its content with the content of the original packet. It works, 
         but may hide some bugs (not tested extensivelly) */
                                            // save this packet somewhere;
      ipq_packet_msg_t *new_pkt=pkt;
                                            // allow the original packet to pass (first instance)
      status=ipq_set_verdict(h, pkt->packet_id, NF_ACCEPT, 0, NULL); 
                                            // wait for a new packet.
                                            // read an IPQ message into buffer.
      unsigned char buffer[BUFFERSIZE];
      status = ipq_read(h, buffer, BUFFERSIZE, 0); // handle h, destination_buffer, buffer_size, timeout
      if (status<0)
         exitWithError(h);
 
                                            // determine the message type -> Packet or error message
      if(ipq_message_type(buffer)==NLMSG_ERROR){
         fprintf(stderr, "Received an error message in doDuplicate(): %d", 
                 ipq_get_msgerr(buffer));   // display the error.
      }
      if(ipq_message_type(buffer)==IPQM_PACKET){
                                            // we received an actual packet of data.
         total_packets++;
         duplicated_packets++;
                                            // replace its contents with the previous packet
                                            // (so that this will be the duplicated one)
         pkt=ipq_get_packet(buffer);        // write the actual packet in pkt
         long id = pkt->packet_id;          // ipq isn't stupid! It knows it has forwarded 
                                            // the packet with the old id, so we must keep 
                                            // the new packets id (they are unique) (the old
                                            // id isn't valid after we set the verdict)
         pkt = new_pkt;                     // overwrite the second packet with the first packet
         pkt->packet_id = id;               // use the second (valid) id
      }
      return 1;                             // send the second, modified packet
   }
   return 0;                                // nothing special to do
}
 
/* Method that decides whether a packet should be mangled */
/* Returns 0 if the packet is to be accepted without modification, 
 *              1 if the packet is to be accepted with modification(s),
 */
int doMangle(struct ipq_handle *h, ipq_packet_msg_t *pkt){
   if(doPercent(cmdline.mangle_percent)==0){ // mangle this packet?
      printf(" mangling ");
      mangled_packets++;
      struct iphdr *iph = ((struct iphdr *)pkt->payload); // get the IP header
      iph->tos=(__u8)24;                    // modify the TOS field (can be any field) to a specific value
      iph->check=0;                         // set the checksum to 0
      iph->check=checksum((unsigned short*)iph,iph->ihl*4); // compute the new checksum
      return 1;                             // forward the modified packet
   }
   return 0;
}
/* ---End of verdict methods--- /*
 
/* Main method
 */
int main(int argc, char **argv){
 
   if(argc<3){                              // not enough arguments, here's a list
      showUsage();
      exit(1);
   }
 
                                            // register a listener for CTRL+C, so that 
                                            // when we stop, we get a nice statistic
   (void) signal(SIGINT, ctrlC);
 
   memset(&cmdline, 0, sizeof(cmdline));    // initialize cmdline with zeros;
   cmdline.reorder_max=1;                   // can't be zero, or it won't be valid
 
   /* If you want to understand how libipq can be used, you shouldn't bother looking over 
      parseCmdline() because it is irrelevant to your goal; it just parses the command 
      line options and populates the cmdline variable. */
   if(parseCmdline(argc, argv)!=0){         // write the data to cmdline
      showUsage();
      exit(1);
   }
 
   if(validateCmdline()!=0){                // check that cmdline has reasonable values
      showUsage();
      exit(1);
   }
 
                                            // initialize random number generator (needed for --delay)
   srand((unsigned int)time( NULL ));
   unsigned char buffer[BUFFERSIZE];        // buffer for packages and ipq messages.
   struct ipq_handle *h;
   int status;
 
                                            // Register a handle with IPQ.
   h = ipq_create_handle(0, PF_INET);       // 0=Flags (not used); PF_INET -> IPV4 
   if (!h)
      exitWithError(h);
 
                                            // Copy entire packets (up to BUFFERSIZE) to user-space
   status = ipq_set_mode(h, IPQ_COPY_PACKET, BUFFERSIZE);
   if (status <0)
      exitWithError(h);
 
                                            // Get the packets and act on them according to the cmdline parameters
                                            // Do this in an infinite loop.
   do{
                                            // read an IPQ message into buffer. The IPQ message isn't the packet!!!
      status = ipq_read(h, buffer, BUFFERSIZE, 0); // handle h, destination_buffer, buffer_size, timeout
      if (status<0)
         exitWithError(h);
 
                                            // determine the message type -> Packet or error message
      if(ipq_message_type(buffer)==NLMSG_ERROR){
         fprintf(stderr, "Received an error message: %d", ipq_get_msgerr(buffer)); // display the error.
      }
      if(ipq_message_type(buffer)==IPQM_PACKET){
                                            // we received an actual packet of data.
         ipq_packet_msg_t *pkt=ipq_get_packet(buffer); // write the actual packet in pkt 
         total_packets++;
 
                                            // all we have to do now is set the verdict!
         int verdict = 0;                   // allow all by default.
         int verdictDrop = 0, verdictDelay = 0, \
             verdictError = 0, verdictReorder = 0, \
             verdictDuplicate = 0, verdictMangle = 0;
 
         printf("\n Packet ");
         if(cmdline.drop==1){               // if we need to drop a percent of  packets
            verdictDrop = doDrop(h, pkt);
         }
         if(verdictDrop !=2 && cmdline.error ==1){ // if it was dropped, don't do anything else to the packet
            verdictError = doError(h, pkt);
         }
         if(verdictDrop !=2 && verdictError !=1 && \
            cmdline.delay ==1){             // if it was dropped or errored, don't do anything else to it
            verdictDelay = doDelay(h, pkt);
         }
         if(verdictDrop !=2 && verdictError !=1 && cmdline.mangle ==1){
            verdictMangle = doMangle(h, pkt);
         }
         if(verdictDrop !=2 && verdictError !=1 && cmdline.reorder ==1){
            verdictReorder = doReorder(h, pkt);
         }
         if(verdictDrop !=2 && verdictError !=1 && cmdline.duplicate ==1){
            verdictDuplicate = doDuplicate(h, pkt);
         }
 
         fflush(stdout);                     // make sure the output is updated
 
         if(verdictDrop ==2)                 // we really need to drop this packet
            verdict = 2;
         else{                               // we need to send a modified packet
            if(verdictError ==1 || verdictMangle ==1 || \
               verdictReorder ==1 || verdictDuplicate ==1)
               verdict = 1;
            else
               verdict = 0;                  // we will send the original packet
         }
 
                                             // we have the verdict, now enforce it!
         if(verdict == 0){
                                             // accept packet without modifications
            status=ipq_set_verdict(h, pkt->packet_id, NF_ACCEPT, 0, NULL); 
                                             // handle, packet id, verdict, data_size, buffer to output.
         }
         if(verdict == 1){
                                             // accept packet with modifications
            status=ipq_set_verdict(h, pkt->packet_id, NF_ACCEPT, pkt->data_len, pkt->payload); 
                                             // handle, packet id, verdict, data_size, buffer to output.
         }
         if(verdict == 2){
                                             // drop packet
            status=ipq_set_verdict(h, pkt->packet_id, NF_DROP, 0, NULL);
                                             // handle, packet id, verdict, data_size, buffer to output.
         }
 
         if(status < 0)
            exitWithError(h);
      }
 
   } while(1);
 
                                             // unreachable code.
   ipq_destroy_handle(h);
   return 0;
}
