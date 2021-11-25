#include <stdint.h>
#include <stdio.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <xtables.h>
#include <linux/netfilter/xt_tcpudp.h>

enum {
	O_SOURCE_PORT = 0,
	O_DEST_PORT,
};

//显示udp匹配的帮助信息
static void udp_help(void)
{
	printf(
"udp match options:\n"
"[!] --source-port port[:port]\n"
" --sport ...\n"
"				match source port(s)\n"
"[!] --destination-port port[:port]\n"
" --dport ...\n"
"				match destination port(s)\n");
}

//udp提供的option entry
#define s struct xt_udp
static const struct xt_option_entry udp_opts[] = {
	{.name = "source-port", .id = O_SOURCE_PORT, .type = XTTYPE_PORTRC,
	 .flags = XTOPT_INVERT | XTOPT_PUT, XTOPT_POINTER(s, spts)},
	{.name = "sport", .id = O_SOURCE_PORT, .type = XTTYPE_PORTRC,
	 .flags = XTOPT_INVERT | XTOPT_PUT, XTOPT_POINTER(s, spts)},
	{.name = "destination-port", .id = O_DEST_PORT, .type = XTTYPE_PORTRC,
	 .flags = XTOPT_INVERT | XTOPT_PUT, XTOPT_POINTER(s, dpts)},
	{.name = "dport", .id = O_DEST_PORT, .type = XTTYPE_PORTRC,
	 .flags = XTOPT_INVERT | XTOPT_PUT, XTOPT_POINTER(s, dpts)},
	XTOPT_TABLEEND,
};
#undef s

//初始化为全匹配
static void udp_init(struct xt_entry_match *m)
{
	struct xt_udp *udpinfo = (struct xt_udp *)m->data;

	udpinfo->spts[1] = udpinfo->dpts[1] = 0xFFFF;
}

static void udp_parse(struct xt_option_call *cb)
{
	struct xt_udp *udpinfo = cb->data;

	xtables_option_parse(cb);
	//标记填充
	switch (cb->entry->id) {
	case O_SOURCE_PORT:
		if (cb->invert)
			udpinfo->invflags |= XT_UDP_INV_SRCPT;
		break;
	case O_DEST_PORT:
		if (cb->invert)
			udpinfo->invflags |= XT_UDP_INV_DSTPT;
		break;
	}
}

static const char *
port_to_service(int port)
{
	const struct servent *service;

	//取udp协议中port对应的服务描述
	if ((service = getservbyport(htons(port), "udp")))
		return service->s_name;

	return NULL;
}

//显示port
static void
print_port(uint16_t port, int numeric/*是否仅考虑数字方式显示*/)
{
	const char *service;

	//如果能找出对应的service,则显示service名称，否则显示port号
	if (numeric || (service = port_to_service(port)) == NULL)
		printf("%u", port);
	else
		printf("%s", service);
}

//port范围显示
static void
print_ports(const char *name, uint16_t min, uint16_t max,
	    int invert, int numeric/*是否仅显示为数字形式*/)
{
	const char *inv = invert ? "!" : "";

	if (min != 0 || max != 0xFFFF || invert) {
		printf(" %s", name);
		if (min == max) {
		    //显示单port情况
			printf(":%s", inv);
			print_port(min, numeric);
		} else {
		    //显示port范围
			printf("s:%s", inv);
			print_port(min, numeric);
			printf(":");
			print_port(max, numeric);
		}
	}
}

//udp匹配形式显示
static void
udp_print(const void *ip, const struct xt_entry_match *match, int numeric/*是否仅显示数字形式*/)
{
	const struct xt_udp *udp = (struct xt_udp *)match->data;

	printf(" udp");
	print_ports("spt", udp->spts[0], udp->spts[1],
		    udp->invflags & XT_UDP_INV_SRCPT,
		    numeric);
	print_ports("dpt", udp->dpts[0], udp->dpts[1],
		    udp->invflags & XT_UDP_INV_DSTPT,
		    numeric);
	//显示不认识的标记
	if (udp->invflags & ~XT_UDP_INV_MASK)
		printf(" Unknown invflags: 0x%X",
		       udp->invflags & ~XT_UDP_INV_MASK);
}

//生成配置命令行
static void udp_save(const void *ip, const struct xt_entry_match *match)
{
	const struct xt_udp *udpinfo = (struct xt_udp *)match->data;

	if (udpinfo->spts[0] != 0
	    || udpinfo->spts[1] != 0xFFFF) {
		if (udpinfo->invflags & XT_UDP_INV_SRCPT)
			printf(" !");
		if (udpinfo->spts[0]
		    != udpinfo->spts[1])
		    //port范围配置
			printf(" --sport %u:%u",
			       udpinfo->spts[0],
			       udpinfo->spts[1]);
		else
		    //单port形式配置
			printf(" --sport %u",
			       udpinfo->spts[0]);
	}

	if (udpinfo->dpts[0] != 0
	    || udpinfo->dpts[1] != 0xFFFF) {
		if (udpinfo->invflags & XT_UDP_INV_DSTPT)
			printf(" !");
		if (udpinfo->dpts[0]
		    != udpinfo->dpts[1])
			printf(" --dport %u:%u",
			       udpinfo->dpts[0],
			       udpinfo->dpts[1]);
		else
			printf(" --dport %u",
			       udpinfo->dpts[0]);
	}
}

static int udp_xlate(struct xt_xlate *xl,
		     const struct xt_xlate_mt_params *params)
{
	const struct xt_udp *udpinfo = (struct xt_udp *)params->match->data;
	char *space= "";

	//udp源port输出
	if (udpinfo->spts[0] != 0 || udpinfo->spts[1] != 0xFFFF) {
		if (udpinfo->spts[0] != udpinfo->spts[1]) {
			xt_xlate_add(xl,"udp sport %s%u-%u",
				   udpinfo->invflags & XT_UDP_INV_SRCPT ?
					 "!= ": "",
				   udpinfo->spts[0], udpinfo->spts[1]);
		} else {
			xt_xlate_add(xl, "udp sport %s%u",
				   udpinfo->invflags & XT_UDP_INV_SRCPT ?
					 "!= ": "",
				   udpinfo->spts[0]);
		}
		space = " ";
	}

	//udp dstport输出
	if (udpinfo->dpts[0] != 0 || udpinfo->dpts[1] != 0xFFFF) {
		if (udpinfo->dpts[0]  != udpinfo->dpts[1]) {
			xt_xlate_add(xl,"%sudp dport %s%u-%u", space,
				   udpinfo->invflags & XT_UDP_INV_SRCPT ?
					 "!= ": "",
				   udpinfo->dpts[0], udpinfo->dpts[1]);
		} else {
			xt_xlate_add(xl,"%sudp dport %s%u", space,
				   udpinfo->invflags & XT_UDP_INV_SRCPT ?
					 "!= ": "",
				   udpinfo->dpts[0]);
		}
	}

	return 1;
}

static struct xtables_match udp_match = {
	.family		= NFPROTO_UNSPEC,
	.name		= "udp",
	.version	= XTABLES_VERSION,
	//支持port范围的匹配
	.size		= XT_ALIGN(sizeof(struct xt_udp)),
	.userspacesize	= XT_ALIGN(sizeof(struct xt_udp)),
	.help		= udp_help,
	.init		= udp_init,
	.print		= udp_print,
	.save		= udp_save,
	.x6_parse	= udp_parse,
	.x6_options	= udp_opts,
	.xlate		= udp_xlate,
};

//iptables的udp扩展
void
_init(void)
{
	xtables_register_match(&udp_match);
}
