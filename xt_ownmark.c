/*
 *	xt_mark - Netfilter module to match NFMARK value
 *
 *	(C) 1999-2001 Marc Boucher <marc@mbsi.ca>
 *	Copyright © CC Computer Consultants GmbH, 2007 - 2008
 *	Jan Engelhardt <jengelh@medozas.de>
 *
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License version 2 as
 *	published by the Free Software Foundation.
 */

#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/bitops.h>

#include <linux/netfilter/xt_ownmark.h>
#include <linux/netfilter/x_tables.h>

MODULE_LICENSE("Dual MIT/GPL");
MODULE_AUTHOR("rektide de la faye <rektide@voodoowarez.com>");
MODULE_DESCRIPTION("Xtables: packet mark owner operations");
MODULE_ALIAS("ipt_ownmark");
MODULE_ALIAS("ip6t_ownmark");
MODULE_ALIAS("ipt_OWNMARK");
MODULE_ALIAS("ip6t_OWNMARK");

static unsigned int
ownmarku_tg(struct sk_buff *skb, const struct xt_action_param *par)
{
	if (skb->sk == NULL || skb->sk->sk_socket == NULL)
		return XT_CONTINUE;
	const struct xt_ownmark_tginfo1 *info = par->targinfo;
	const struct file *filp = skb->sk->sk_socket->file;

	if(info->id_min != 0){
		kuid_t id_min = make_kuid(&init_user_ns, info->uid_min)
		if (uid_lt(filp->f_cred->fsuid, id_min))
			return XT_CONTINUE;
	}
	if(info->id_max != 0){
		kuid_t id_max = make_kuid(&init_user_ns, info->uid_max);
		if ((uid_gt(filp->f_cred->fsuid, id_max))
			return XT_CONTINUE;
	}

	__u32 val = rol32(filp->f_cred->uid.val,info->shift);
	if(info->mask == 0)
		skb->mark = val;
	else
		skb->mark = val | (skb->mark & rol32(~info->mask,info->shift));
	return XT_CONTINUE;
}

static struct xt_target ownmark_tg_reg __read_mostly = {
	.name           = "OWNMARK",
	.revision       = 1,
	.family         = NFPROTO_UNSPEC,
	.target         = ownmark_tg,
	.targetsize     = sizeof(struct xt_ownmark_tginfo1),
	.me             = THIS_MODULE,
};

static int __init ownmark_mt_init(void)
{
	return xt_register_target(&ownmark_tg_reg);
}

static void __exit ownmark_mt_exit(void)
{
	xt_unregister_target(&ownmark_tg_reg);
}

module_init(ownmark_mt_init);
module_exit(ownmark_mt_exit);
