/******************************
 * Code in Chapter 14
 ******************************/



/**********************************************
 * Listing 14.1: Basic kernel module (kMod.c)
 **********************************************/

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

static int kmodule_init(void) {
	printk(KERN_INFO "Initializing this module\n"); 
	return 0;
}

static void kmodule_exit(void) {
	printk(KERN_INFO "Module cleanup\n"); 
}

module_init(kmodule_init);      
module_exit(kmodule_exit);     

MODULE_LICENSE("GPL");



/**********************************************
 * Makefile on Page 260 (Section 14.3.2)
 **********************************************/

obj-m += kMod.o
all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean



/**********************************************
 * Listing 14.2: Packet filtering (telnetFilter.c)
 **********************************************/

unsigned int telnetFilter(unsigned int hooknum, struct sk_buff *skb,
      const struct net_device *in, const struct net_device *out,
      int (*okfn)(struct sk_buff *)) {
  struct iphdr *iph;
  struct tcphdr *tcph;

  iph = ip_hdr(skb);
  tcph = (void *)iph+iph->ihl*4;

  if (iph->protocol == IPPROTO_TCP && tcph->dest == htons(23)) {
    printk(KERN_INFO "Dropping telnet packet to %d.%d.%d.%d\n",
	((unsigned char *)&iph->daddr)[0],
	((unsigned char *)&iph->daddr)[1],
	((unsigned char *)&iph->daddr)[2],
	((unsigned char *)&iph->daddr)[3]);
    return NF_DROP;
  } else {
    return NF_ACCEPT;
  }
}


/**********************************************
 * Listing 14.3: Simple netfilter module (telnetFilter.c)
 **********************************************/

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>

static struct nf_hook_ops telnetFilterHook;

/* The implementation of the telnetFilter function is omitted here; 
   it was shown earlier in (*@Listing~\ref{firewall:code:telnetFilter}@*). */

int setUpFilter(void) {
	printk(KERN_INFO "Registering a Telnet filter.\n");
	telnetFilterHook.hook = telnetFilter; (*@\label{firewall:line:telnetHookfn}@*)
	telnetFilterHook.hooknum = NF_INET_POST_ROUTING; 
	telnetFilterHook.pf = PF_INET;
	telnetFilterHook.priority = NF_IP_PRI_FIRST;

	// Register the hook.
	nf_register_hook(&telnetFilterHook);
	return 0;
}

void removeFilter(void) {
	printk(KERN_INFO "Telnet filter is being removed.\n");
	nf_unregister_hook(&telnetFilterHook);
}

module_init(setUpFilter);
module_exit(removeFilter);

MODULE_LICENSE("GPL");



/**********************************************
 * iptables commands on Pages 268-269 (Section 14.5.4)
 **********************************************/

// Set up all the default policies to ACCEPT packets.
$ sudo iptables -P INPUT ACCEPT
$ sudo iptables -P OUTPUT ACCEPT
$ sudo iptables -P FORWARD ACCEPT

// Flush all existing configurations.
$ sudo iptables -F


// Allow all incoming TCP packets bound to destination port 22.
// -A INPUT: Append to existing INPUT chain rules.
// -p tcp: Select TCP packets
// -dport 22: Select packets with destination port 22.
// -j ACCEPT: Accept all the packets that are selected.
$ sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT


// Similarly, accept all packets bound to destination port 80.
$ sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT


// Allow all outgoing TCP traffic.
// -A OUTPUT: Append to existing OUTPUT chain rules.
// -p tcp: Apply on TCP protocol packets
// -m tcp: Further apply matching rules defined in 'tcp' module.
// -j ACCEPT: Let the selected packets through.
$ sudo iptables -A OUTPUT -p tcp -m tcp -j ACCEPT


// -I INPUT 1 : Insert a rule in the 1st position of the INPUT chain.
// -i lo : Select packets bound for the loopback (lo) interface.
// -j ACCEPT: Accept all the packets that are selected.
$ sudo iptables -I INPUT 1 -i lo -j ACCEPT


// Allow DNS queries and replies to pass through.
$ sudo iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
$ sudo iptables -A INPUT -p udp --sport 53 -j ACCEPT


// Setting default filter policy to DROP.
$ sudo iptables -P INPUT DROP
$ sudo iptables -P OUTPUT DROP
$ sudo iptables -P FORWARD DROP



/**********************************************
 * Code on Page 270 (Section 14.5.4)
 **********************************************/

$ more cleanup.sh 
#!/bin/sh

# Set up all the default policies to ACCEPT packets.
iptables -P INPUT ACCEPT
iptables -P OUTPUT ACCEPT
iptables -P FORWARD ACCEPT

#Flush all existing configrations.
iptables -F

$ sudo ./cleanup.sh



/**********************************************
 * iptables command on Page 272 (Section 14.6.3)
 **********************************************/

// -A OUTPUT: Append to existing OUTPUT chain rules.
// -p tcp: Apply on TCP protocol packets.
// -m conntrack: Apply the rules from conntrack module.
// --ctsate ESTABLISHED,RELATED: Look for traffic in ESTABLISHED or RELATED states.
// -j ACCEPT: Let the selected packets through.

$ sudo iptables -A OUTPUT -p tcp -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT



