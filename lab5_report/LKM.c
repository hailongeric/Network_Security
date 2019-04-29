#include<linux/module.h>
#include<linux/kernel.h>
#include<linux/netfilter.h>
#include<linux/netfilter_ipv4.h>
#include<linux/ip.h>
#include<linux/tcp.h>
#include<linux/socket.h>
#include<linux/in.h>
#include<linux/inet.h>
#include<net/net_namespace.h>

/*int init_module(void){
	printk(KERN_INFO "Hello World!\n");
	return 0;
}
void cleanup_module(void){
	printk(KERN_INFO "Bye-bye World!.\n");
}*/

/* This is the structure we shall use to register our function */ 
static struct nf_hook_ops nfho;

unsigned int inet_addr(char *str) 
{ 
	int a,b,c,d; 
	char arr[4]; 
	sscanf(str,"%d.%d.%d.%d",&a,&b,&c,&d); 
	arr[0] = a; arr[1] = b; arr[2] = c; arr[3] = d; 
	return *(unsigned int*)arr; 
} 


/* This is the hook function itself */ 
unsigned int hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) { 

/* This is where you can inspect the packet contained in the structure pointed by skb, 
 *and decide whether to accept or drop it. You can even modify the packet */

	printk(KERN_INFO "this is a hook function!\n"); 
	struct iphdr *ip_header = (struct iphdr *)skb_network_header(skb); 
	unsigned int src_ip = (unsigned int)ip_header->saddr; 
	unsigned int dest_ip = (unsigned int)ip_header->daddr;
	
	struct tcphdr *tcp_header = (struct tcphdr *)skb_transport_header(skb); 
	unsigned int src_port = (unsigned int)ntohs(tcp_header->source); 
	unsigned int dest_port = (unsigned int)ntohs(tcp_header->dest);

	unsigned int block_A_addr = inet_addr("10.0.2.4");
	unsigned int block_B_addr = inet_addr("10.0.2.5");
	unsigned int block_web = inet_addr("202.120.224.115");	
	
	printk(KERN_INFO "dst_ip:%x port:%d\n",dest_ip,dest_port);
	printk(KERN_INFO "src_ip:%x port:%d\n",src_ip,src_port);
	//Prevent A from doing telnet to Machine B.	
	if(src_ip == block_A_addr){
		printk(KERN_INFO "okok this is 10.0.2.4");
		return NF_DROP;
	}
	
	if(dest_ip == block_A_addr && src_port == 23){
		printk(KERN_INFO "block A-B\n");
		return NF_DROP;
	}
	
	//Prevent B from doing telnet to Machine A.
	if(src_ip == block_B_addr && dest_port == 23){
		printk(KERN_INFO "block B-A\n");
		return NF_DROP;
	}

	//Prevent A from visiting an external web site. 
	if(src_ip == block_web){
		printk(KERN_INFO "block WEB fudan\n");
		return NF_DROP;
	}
	
	//if ip error ,drop 
	if((int)ip_header->ihl != 5 ){
		printk(KERN_INFO "block error%x\n",ip_header->ihl);
		return NF_DROP;
	}
	//close ftp dynamic port 21
	if(dest_ip == block_A_addr && dest_port ==21){
		printk(KERN_INFO "block port 21\n");
		return NF_DROP;
	}


	// In this example, we simply drop all packets 
	return NF_ACCEPT;    /* Drop ALL packets */
		
}

MODULE_LICENSE("GPL");

/* Initialization routine */ 

int init_module(void) { 
	
	printk(KERN_INFO "Hello World!\n"); 
	
	/* Fill in our hook structure */ 
	
	nfho.hook = hook_func;	/* Handler function */ 

	nfho.hooknum = NF_INET_PRE_ROUTING;	/* First hook for IPv4 */ 

	nfho.pf = PF_INET; 

	nfho.priority = NF_IP_PRI_FIRST; 	/* Make our function first */

	nf_register_net_hook(&init_net,&nfho); 

	return 0;

}



/* Cleanup routine */ 

void cleanup_module(void){ 
	
	printk(KERN_INFO "Bye - bye hailong!!!\n");
	nf_unregister_net_hook(&init_net,&nfho); 

}



