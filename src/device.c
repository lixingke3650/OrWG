// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include "queueing.h"
#include "socket.h"
#include "timers.h"
#include "device.h"
#include "ratelimiter.h"
#include "peer.h"
#include "messages.h"

#include <linux/module.h>
#include <linux/rtnetlink.h>
#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/if_arp.h>
#include <linux/icmp.h>
#include <linux/suspend.h>
#include <net/icmp.h>
#include <net/rtnetlink.h>
#include <net/ip_tunnels.h>
#include <net/addrconf.h>

static LIST_HEAD(device_list);

static int wg_open(struct net_device *dev)
{
	struct in_device *dev_v4 = __in_dev_get_rtnl(dev);
#ifndef COMPAT_CANNOT_USE_IN6_DEV_GET
	struct inet6_dev *dev_v6 = __in6_dev_get(dev);
#endif
	struct wg_device *wg = netdev_priv(dev);
	struct wg_peer *peer;
	int ret;

	if (dev_v4) {
		/* At some point we might put this check near the ip_rt_send_
		 * redirect call of ip_forward in net/ipv4/ip_forward.c, similar
		 * to the current secpath check.
		 */
		IN_DEV_CONF_SET(dev_v4, SEND_REDIRECTS, false);
		IPV4_DEVCONF_ALL(dev_net(dev), SEND_REDIRECTS) = false;
	}
#ifndef COMPAT_CANNOT_USE_IN6_DEV_GET
	if (dev_v6)
#ifndef COMPAT_CANNOT_USE_DEV_CNF
		dev_v6->cnf.addr_gen_mode = IN6_ADDR_GEN_MODE_NONE;
#else
		dev_v6->addr_gen_mode = IN6_ADDR_GEN_MODE_NONE;
#endif
#endif

	ret = wg_socket_init(wg, wg->incoming_port);
	if (ret < 0)
		return ret;
	mutex_lock(&wg->device_update_lock);
	list_for_each_entry(peer, &wg->peer_list, peer_list) {
		wg_packet_send_staged_packets(peer);
		if (peer->persistent_keepalive_interval)
			wg_packet_send_keepalive(peer);
	}
	mutex_unlock(&wg->device_update_lock);
	return 0;
}

#ifdef CONFIG_PM_SLEEP
static int wg_pm_notification(struct notifier_block *nb, unsigned long action,
			      void *data)
{
	struct wg_device *wg;
	struct wg_peer *peer;

	/* If the machine is constantly suspending and resuming, as part of
	 * its normal operation rather than as a somewhat rare event, then we
	 * don't actually want to clear keys.
	 */
	if (IS_ENABLED(CONFIG_PM_AUTOSLEEP) || IS_ENABLED(CONFIG_ANDROID))
		return 0;

	if (action != PM_HIBERNATION_PREPARE && action != PM_SUSPEND_PREPARE)
		return 0;

	rtnl_lock();
	list_for_each_entry(wg, &device_list, device_list) {
		mutex_lock(&wg->device_update_lock);
		list_for_each_entry(peer, &wg->peer_list, peer_list) {
			del_timer(&peer->timer_zero_key_material);
			wg_noise_handshake_clear(&peer->handshake);
			wg_noise_keypairs_clear(&peer->keypairs);
		}
		mutex_unlock(&wg->device_update_lock);
	}
	rtnl_unlock();
	rcu_barrier();
	return 0;
}

static struct notifier_block pm_notifier = { .notifier_call = wg_pm_notification };
#endif

static int wg_stop(struct net_device *dev)
{
	struct wg_device *wg = netdev_priv(dev);
	struct wg_peer *peer;

	mutex_lock(&wg->device_update_lock);
	list_for_each_entry(peer, &wg->peer_list, peer_list) {
		wg_packet_purge_staged_packets(peer);
		wg_timers_stop(peer);
		wg_noise_handshake_clear(&peer->handshake);
		wg_noise_keypairs_clear(&peer->keypairs);
		wg_noise_reset_last_sent_handshake(&peer->last_sent_handshake);
	}
	mutex_unlock(&wg->device_update_lock);
	skb_queue_purge(&wg->incoming_handshakes);
	wg_socket_reinit(wg, NULL, NULL);
	return 0;
}

static netdev_tx_t wg_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct wg_device *wg = netdev_priv(dev);
	struct sk_buff_head packets;
	struct wg_peer *peer;
	struct sk_buff *next;
	sa_family_t family;
	u32 mtu;
	int ret;

	if (unlikely(wg_skb_examine_untrusted_ip_hdr(skb) != skb->protocol)) {
		ret = -EPROTONOSUPPORT;
		net_dbg_ratelimited("%s: Invalid IP packet\n", dev->name);
		goto err;
	}

	peer = wg_allowedips_lookup_dst(&wg->peer_allowedips, skb);
	if (unlikely(!peer)) {
		ret = -ENOKEY;
		if (skb->protocol == htons(ETH_P_IP))
			net_dbg_ratelimited("%s: No peer has allowed IPs matching %pI4\n",
					    dev->name, &ip_hdr(skb)->daddr);
		else if (skb->protocol == htons(ETH_P_IPV6))
			net_dbg_ratelimited("%s: No peer has allowed IPs matching %pI6\n",
					    dev->name, &ipv6_hdr(skb)->daddr);
		goto err;
	}

	family = READ_ONCE(peer->endpoint.addr.sa_family);
	if (unlikely(family != AF_INET && family != AF_INET6)) {
		ret = -EDESTADDRREQ;
		net_dbg_ratelimited("%s: No valid endpoint has been configured or discovered for peer %llu\n",
				    dev->name, peer->internal_id);
		goto err_peer;
	}

	mtu = skb_dst(skb) ? dst_mtu(skb_dst(skb)) : dev->mtu;

	__skb_queue_head_init(&packets);
	if (!skb_is_gso(skb)) {
		skb_mark_not_on_list(skb);
	} else {
		struct sk_buff *segs = skb_gso_segment(skb, 0);

		if (unlikely(IS_ERR(segs))) {
			ret = PTR_ERR(segs);
			goto err_peer;
		}
		dev_kfree_skb(skb);
		skb = segs;
	}

	skb_list_walk_safe(skb, skb, next) {
		skb_mark_not_on_list(skb);

		skb = skb_share_check(skb, GFP_ATOMIC);
		if (unlikely(!skb))
			continue;

		/* We only need to keep the original dst around for icmp,
		 * so at this point we're in a position to drop it.
		 */
		skb_dst_drop(skb);

		PACKET_CB(skb)->mtu = mtu;

		__skb_queue_tail(&packets, skb);
	}

	spin_lock_bh(&peer->staged_packet_queue.lock);
	/* If the queue is getting too big, we start removing the oldest packets
	 * until it's small again. We do this before adding the new packet, so
	 * we don't remove GSO segments that are in excess.
	 */
	while (skb_queue_len(&peer->staged_packet_queue) > MAX_STAGED_PACKETS) {
		dev_kfree_skb(__skb_dequeue(&peer->staged_packet_queue));
		++dev->stats.tx_dropped;
	}
	skb_queue_splice_tail(&packets, &peer->staged_packet_queue);
	spin_unlock_bh(&peer->staged_packet_queue.lock);

	wg_packet_send_staged_packets(peer);

	wg_peer_put(peer);
	return NETDEV_TX_OK;

err_peer:
	wg_peer_put(peer);
err:
	++dev->stats.tx_errors;
	if (skb->protocol == htons(ETH_P_IP))
		icmp_send(skb, ICMP_DEST_UNREACH, ICMP_HOST_UNREACH, 0);
	else if (skb->protocol == htons(ETH_P_IPV6))
		icmpv6_send(skb, ICMPV6_DEST_UNREACH, ICMPV6_ADDR_UNREACH, 0);
	kfree_skb(skb);
	return ret;
}

static const struct net_device_ops netdev_ops = {
	.ndo_open		= wg_open,
	.ndo_stop		= wg_stop,
	.ndo_start_xmit		= wg_xmit,
	.ndo_get_stats64	= ip_tunnel_get_stats64
};

static void wg_destruct(struct net_device *dev)
{
	struct wg_device *wg = netdev_priv(dev);

	rtnl_lock();
	list_del(&wg->device_list);
	rtnl_unlock();
	mutex_lock(&wg->device_update_lock);
	wg->incoming_port = 0;
	wg_socket_reinit(wg, NULL, NULL);
	/* The final references are cleared in the below calls to destroy_workqueue. */
	wg_peer_remove_all(wg);
	destroy_workqueue(wg->handshake_receive_wq);
	destroy_workqueue(wg->handshake_send_wq);
	destroy_workqueue(wg->packet_crypt_wq);
	wg_packet_queue_free(&wg->decrypt_queue, true);
	wg_packet_queue_free(&wg->encrypt_queue, true);
	rcu_barrier(); /* Wait for all the peers to be actually freed. */
	wg_ratelimiter_uninit();
	memzero_explicit(&wg->static_identity, sizeof(wg->static_identity));
	skb_queue_purge(&wg->incoming_handshakes);
	free_percpu(dev->tstats);
	free_percpu(wg->incoming_handshakes_worker);
	if (wg->have_creating_net_ref)
		put_net(wg->creating_net);
	kvfree(wg->index_hashtable);
	kvfree(wg->peer_hashtable);
	mutex_unlock(&wg->device_update_lock);

	pr_debug("%s: Interface deleted\n", dev->name);
	free_netdev(dev);
}

static const struct device_type device_type = { .name = KBUILD_MODNAME };

static void wg_setup(struct net_device *dev)
{
	struct wg_device *wg = netdev_priv(dev);
	enum { WG_NETDEV_FEATURES = NETIF_F_HW_CSUM | NETIF_F_RXCSUM |
				    NETIF_F_SG | NETIF_F_GSO |
				    NETIF_F_GSO_SOFTWARE | NETIF_F_HIGHDMA };

	dev->netdev_ops = &netdev_ops;
	dev->hard_header_len = 0;
	dev->addr_len = 0;
	dev->needed_headroom = DATA_PACKET_HEAD_ROOM;
	dev->needed_tailroom = noise_encrypted_len(MESSAGE_PADDING_MULTIPLE);
	dev->type = ARPHRD_NONE;
	dev->flags = IFF_POINTOPOINT | IFF_NOARP;
#ifndef COMPAT_CANNOT_USE_IFF_NO_QUEUE
	dev->priv_flags |= IFF_NO_QUEUE;
#else
	dev->tx_queue_len = 0;
#endif
	dev->features |= NETIF_F_LLTX;
	dev->features |= WG_NETDEV_FEATURES;
	dev->hw_features |= WG_NETDEV_FEATURES;
	dev->hw_enc_features |= WG_NETDEV_FEATURES;
	dev->mtu = ETH_DATA_LEN - MESSAGE_MINIMUM_LENGTH -
		   sizeof(struct udphdr) -
		   max(sizeof(struct ipv6hdr), sizeof(struct iphdr));

	SET_NETDEV_DEVTYPE(dev, &device_type);

	/* We need to keep the dst around in case of icmp replies. */
	netif_keep_dst(dev);

	memset(wg, 0, sizeof(*wg));
	wg->dev = dev;
}

static int wg_newlink(struct net *src_net, struct net_device *dev,
		      struct nlattr *tb[], struct nlattr *data[],
		      struct netlink_ext_ack *extack)
{
	struct wg_device *wg = netdev_priv(dev);
	int ret = -ENOMEM;

	wg->creating_net = src_net;
	init_rwsem(&wg->static_identity.lock);
	mutex_init(&wg->socket_update_lock);
	mutex_init(&wg->device_update_lock);
	skb_queue_head_init(&wg->incoming_handshakes);
	wg_allowedips_init(&wg->peer_allowedips);
	wg_cookie_checker_init(&wg->cookie_checker, wg);
	INIT_LIST_HEAD(&wg->peer_list);
	wg->device_update_gen = 1;

	wg->peer_hashtable = wg_pubkey_hashtable_alloc();
	if (!wg->peer_hashtable)
		return ret;

	wg->index_hashtable = wg_index_hashtable_alloc();
	if (!wg->index_hashtable)
		goto err_free_peer_hashtable;

	dev->tstats = netdev_alloc_pcpu_stats(struct pcpu_sw_netstats);
	if (!dev->tstats)
		goto err_free_index_hashtable;

	wg->incoming_handshakes_worker =
		wg_packet_percpu_multicore_worker_alloc(
				wg_packet_handshake_receive_worker, wg);
	if (!wg->incoming_handshakes_worker)
		goto err_free_tstats;

	wg->handshake_receive_wq = alloc_workqueue("wg-kex-%s",
			WQ_CPU_INTENSIVE | WQ_FREEZABLE, 0, dev->name);
	if (!wg->handshake_receive_wq)
		goto err_free_incoming_handshakes;

	wg->handshake_send_wq = alloc_workqueue("wg-kex-%s",
			WQ_UNBOUND | WQ_FREEZABLE, 0, dev->name);
	if (!wg->handshake_send_wq)
		goto err_destroy_handshake_receive;

	wg->packet_crypt_wq = alloc_workqueue("wg-crypt-%s",
			WQ_CPU_INTENSIVE | WQ_MEM_RECLAIM, 0, dev->name);
	if (!wg->packet_crypt_wq)
		goto err_destroy_handshake_send;

	ret = wg_packet_queue_init(&wg->encrypt_queue, wg_packet_encrypt_worker,
				   true, MAX_QUEUED_PACKETS);
	if (ret < 0)
		goto err_destroy_packet_crypt;

	ret = wg_packet_queue_init(&wg->decrypt_queue, wg_packet_decrypt_worker,
				   true, MAX_QUEUED_PACKETS);
	if (ret < 0)
		goto err_free_encrypt_queue;

	ret = wg_ratelimiter_init();
	if (ret < 0)
		goto err_free_decrypt_queue;

	ret = register_netdevice(dev);
	if (ret < 0)
		goto err_uninit_ratelimiter;

	list_add(&wg->device_list, &device_list);

	/* We wait until the end to assign priv_destructor, so that
	 * register_netdevice doesn't call it for us if it fails.
	 */
	dev->priv_destructor = wg_destruct;

	pr_debug("%s: Interface created\n", dev->name);
	return ret;

err_uninit_ratelimiter:
	wg_ratelimiter_uninit();
err_free_decrypt_queue:
	wg_packet_queue_free(&wg->decrypt_queue, true);
err_free_encrypt_queue:
	wg_packet_queue_free(&wg->encrypt_queue, true);
err_destroy_packet_crypt:
	destroy_workqueue(wg->packet_crypt_wq);
err_destroy_handshake_send:
	destroy_workqueue(wg->handshake_send_wq);
err_destroy_handshake_receive:
	destroy_workqueue(wg->handshake_receive_wq);
err_free_incoming_handshakes:
	free_percpu(wg->incoming_handshakes_worker);
err_free_tstats:
	free_percpu(dev->tstats);
err_free_index_hashtable:
	kvfree(wg->index_hashtable);
err_free_peer_hashtable:
	kvfree(wg->peer_hashtable);
	return ret;
}

static struct rtnl_link_ops link_ops __read_mostly = {
	.kind			= KBUILD_MODNAME,
	.priv_size		= sizeof(struct wg_device),
	.setup			= wg_setup,
	.newlink		= wg_newlink,
};

static int wg_netdevice_notification(struct notifier_block *nb,
				     unsigned long action, void *data)
{
	struct net_device *dev = ((struct netdev_notifier_info *)data)->dev;
	struct wg_device *wg = netdev_priv(dev);

	ASSERT_RTNL();

	if (action != NETDEV_REGISTER || dev->netdev_ops != &netdev_ops)
		return 0;

	if (dev_net(dev) == wg->creating_net && wg->have_creating_net_ref) {
		put_net(wg->creating_net);
		wg->have_creating_net_ref = false;
	} else if (dev_net(dev) != wg->creating_net &&
		   !wg->have_creating_net_ref) {
		wg->have_creating_net_ref = true;
		get_net(wg->creating_net);
	}
	return 0;
}

static struct notifier_block netdevice_notifier = {
	.notifier_call = wg_netdevice_notification
};

int __init wg_device_init(void)
{
	int ret;

#ifdef CONFIG_PM_SLEEP
	ret = register_pm_notifier(&pm_notifier);
	if (ret)
		return ret;
#endif

	ret = register_netdevice_notifier(&netdevice_notifier);
	if (ret)
		goto error_pm;

	ret = rtnl_link_register(&link_ops);
	if (ret)
		goto error_netdevice;

	return 0;

error_netdevice:
	unregister_netdevice_notifier(&netdevice_notifier);
error_pm:
#ifdef CONFIG_PM_SLEEP
	unregister_pm_notifier(&pm_notifier);
#endif
	return ret;
}

void wg_device_uninit(void)
{
	rtnl_link_unregister(&link_ops);
	unregister_netdevice_notifier(&netdevice_notifier);
#ifdef CONFIG_PM_SLEEP
	unregister_pm_notifier(&pm_notifier);
#endif
	rcu_barrier();
}

static __le32 SBox[WG_DEVICE_SBOX_SIZE] = {
	0x9EF5, 0xD2D0, 0x5A2C, 0xAE26, 
	0x2557, 0x1425, 0xC30A, 0x50F9, 
	0xA91D, 0x203A, 0xE7F5, 0xEDC4, 
	0x9823, 0xE3EA, 0x47A3, 0x1A57, 
	0x5E71, 0x4B9F, 0x72D7, 0x1A36, 
	0xBFDB, 0xBD1F, 0x024B, 0x4471, 
	0x9927, 0x3D6A, 0xD5E4, 0x088F, 
	0x26BA, 0xC9BC, 0x8667, 0xD654, 
	0x78B0, 0x74E6, 0x675C, 0x313D, 
	0x7F7F, 0xB012, 0xB405, 0x34A6, 
	0x769C, 0x1271, 0x05A5, 0xCBEE, 
	0xDC83, 0xEEC1, 0x47FB, 0x32E7, 
	0x8A75, 0x274A, 0x8CE3, 0x9C6B, 
	0x1BCD, 0x88DE, 0xAAED, 0xE4F8, 
	0xD139, 0xA66C, 0x80D4, 0xC6D1, 
	0x301C, 0x79D0, 0x39EC, 0x66D6, 
	0xC8CF, 0x4C3D, 0x09CB, 0xB26A, 
	0x46AA, 0xC189, 0xD311, 0xDD14, 
	0x4011, 0xA803, 0x7CFF, 0x2D75, 
	0xD8AF, 0xE9DA, 0x34FE, 0x52C9, 
	0xE0C0, 0x771D, 0x73C7, 0xE146, 
	0xA932, 0x0EBD, 0x4230, 0x7F46, 
	0xC033, 0x3FF9, 0x4109, 0x5D96, 
	0x42FC, 0xFF1B, 0x1D7B, 0xB49F, 
	0x7B68, 0xA626, 0x7415, 0x0EE4, 
	0xEEFB, 0xDEE9, 0x5FBF, 0x1CE5, 
	0xD413, 0x58D2, 0xB901, 0xD6C3, 
	0x4101, 0xD9FC, 0x30A4, 0xC049, 
	0x2BED, 0x9704, 0x7637, 0xAE5D, 
	0xA992, 0x7E00, 0xAA47, 0x8EDA, 
	0x9876, 0x6FE3, 0x1EBB, 0x2E24, 
	0x7461, 0xC5CE, 0xC0DC, 0x1E4B, 
	0x2889, 0x8131, 0x5D51, 0x8EFB, 
	0x45F2, 0x8B8C, 0x63B5, 0x39D2, 
	0x60AC, 0xD1DE, 0x8D55, 0x10AA, 
	0xBF75, 0xF516, 0x37B1, 0x5397, 
	0xBF9C, 0xAAF9, 0xF71F, 0x09FD, 
	0xB12D, 0xB8FA, 0xFD61, 0xEA33, 
	0xDE56, 0x9709, 0xED1B, 0xE1C1, 
	0xE369, 0xA014, 0xB062, 0x1658, 
	0x6360, 0x486C, 0x05B8, 0x9C32, 
	0xCEE7, 0x8FEF, 0x3BE5, 0xAB91, 
	0xA913, 0xD941, 0x6999, 0x6A3B, 
	0x1567, 0xDF21, 0x5B2D, 0x49C5, 
	0x039D, 0xA715, 0xFC37, 0x9592, 
	0xE16F, 0x2443, 0xD4EB, 0x38F4, 
	0xC006, 0x8710, 0x7679, 0x09DA, 
	0x3B4A, 0x3FE4, 0xE4F8, 0x5A48, 
	0x8510, 0xB313, 0x7BD1, 0x14B4, 
	0xF6F7, 0x817D, 0xFFF5, 0x4F79, 
	0xCDF0, 0xC00D, 0x87DF, 0x9158, 
	0x508B, 0xDAC5, 0x9F45, 0xC33E, 
	0x82E3, 0xE1C1, 0x62B3, 0xADE6, 
	0x5059, 0x9500, 0x9653, 0x89A2, 
	0x51F2, 0x73BE, 0x629C, 0x3C5F, 
	0x821E, 0xB103, 0xF996, 0xB252, 
	0xBE99, 0x73F7, 0x47F5, 0x82C2, 
	0x4C19, 0xE258, 0xF629, 0x9162, 
	0x08D7, 0x252A, 0x41C1, 0xD3B4, 
	0x0E50, 0xEB23, 0x9535, 0xC55A, 
	0x2D3D, 0x4CF5, 0x8C84, 0x6832, 
	0x9FA0, 0x7EB1, 0x988C, 0x7B33, 
	0x9A9D, 0xF31C, 0x67FC, 0x8150, 
	0x2887, 0x5A73, 0xA491, 0x7A94, 
};
static u16 SBox_Counter = 0;

__le32 wg_device_get_random(void)
{
	if (SBox_Counter >= WG_DEVICE_SBOX_SIZE) {
		SBox_Counter = 0;
	}
	return SBox[SBox_Counter++];
}