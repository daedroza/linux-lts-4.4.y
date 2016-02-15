#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/cryptohash.h>
#include <linux/module.h>
#include <linux/cache.h>
#include <linux/random.h>
#include <linux/hrtimer.h>
#include <linux/ktime.h>
#include <linux/string.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

#include <net/tcp.h>
#include <net/secure_seq.h>

#if IS_ENABLED(CONFIG_IPV6) || IS_ENABLED(CONFIG_INET)
#define NET_SECRET_SIZE (MD5_MESSAGE_BYTES / 4)

static u32 net_secret[NET_SECRET_SIZE] ____cacheline_aligned;

static __always_inline void net_secret_init(void)
{
	net_get_random_once(net_secret, sizeof(net_secret));
}
#endif

#ifdef CONFIG_INET
static u32 seq_scale(u32 seq)
{
	/*
	 *	As close as possible to RFC 793, which
	 *	suggests using a 250 kHz clock.
	 *	Further reading shows this assumes 2 Mb/s networks.
	 *	For 10 Mb/s Ethernet, a 1 MHz clock is appropriate.
	 *	For 10 Gb/s Ethernet, a 1 GHz clock should be ok, but
	 *	we also need to limit the resolution so that the u32 seq
	 *	overlaps less than one time per MSL (2 minutes).
	 *	Choosing a clock of 64 ns period is OK. (period of 274 s)
	 */
	return seq + (ktime_get_real_ns() >> 6);
}
#endif

#ifdef CONFIG_TCP_STEALTH
u32 tcp_stealth_sequence_number(struct sock *sk, __be32 *daddr,
				u32 daddr_size, __be16 dport)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct tcp_md5sig_key *md5;

	__u32 sec[MD5_MESSAGE_BYTES / sizeof(__u32)];
	__u32 i;
	__u32 tsval = 0;

	__be32 iv[MD5_DIGEST_WORDS] = { 0 };
	__be32 isn;

	memcpy(iv, daddr, (daddr_size > sizeof(iv)) ? sizeof(iv) : daddr_size);

#ifdef CONFIG_TCP_MD5SIG
	md5 = tp->af_specific->md5_lookup(sk, sk);
#else
	md5 = NULL;
#endif
	if (likely(sysctl_tcp_timestamps && !md5) || tp->stealth.saw_tsval)
		tsval = tp->stealth.mstamp.stamp_jiffies;

	((__be16 *)iv)[2] ^= cpu_to_be16(tp->stealth.integrity_hash);
	iv[2] ^= cpu_to_be32(tsval);
	((__be16 *)iv)[6] ^= dport;

	for (i = 0; i < MD5_DIGEST_WORDS; i++)
		iv[i] = le32_to_cpu(iv[i]);
	for (i = 0; i < MD5_MESSAGE_BYTES / sizeof(__le32); i++)
		sec[i] = le32_to_cpu(((__le32 *)tp->stealth.secret)[i]);

	md5_transform(iv, sec);

	isn = cpu_to_be32(iv[0]) ^ cpu_to_be32(iv[1]) ^
	      cpu_to_be32(iv[2]) ^ cpu_to_be32(iv[3]);

	if (tp->stealth.mode & TCP_STEALTH_MODE_INTEGRITY)
		be32_isn_to_be16_ih(isn) =
			cpu_to_be16(tp->stealth.integrity_hash);

	return be32_to_cpu(isn);
}
EXPORT_SYMBOL(tcp_stealth_sequence_number);

u32 tcp_stealth_do_auth(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct tcphdr *th = tcp_hdr(skb);
	__be32 isn = th->seq;
	__be32 hash;
	__be32 *daddr;
	u32 daddr_size;

	tp->stealth.saw_tsval =
		tcp_parse_tsval_option(&tp->stealth.mstamp.stamp_jiffies, th);

	if (tp->stealth.mode & TCP_STEALTH_MODE_INTEGRITY_LEN)
		tp->stealth.integrity_hash =
			be16_to_cpu(be32_isn_to_be16_ih(isn));

	switch (tp->inet_conn.icsk_inet.sk.sk_family) {
#if IS_ENABLED(CONFIG_IPV6)
	case PF_INET6:
		daddr_size = sizeof(ipv6_hdr(skb)->daddr.s6_addr32);
		daddr = ipv6_hdr(skb)->daddr.s6_addr32;
	break;
#endif
	case PF_INET:
		daddr_size = sizeof(ip_hdr(skb)->daddr);
		daddr = &ip_hdr(skb)->daddr;
	break;
	default:
		pr_err("TCP Stealth: Unknown network layer protocol, stop!\n");
		return 1;
	}

	hash = tcp_stealth_sequence_number(sk, daddr, daddr_size, th->dest);
	cpu_to_be32s(&hash);

	if (tp->stealth.mode & TCP_STEALTH_MODE_AUTH &&
	    tp->stealth.mode & TCP_STEALTH_MODE_INTEGRITY_LEN &&
	    be32_isn_to_be16_av(isn) == be32_isn_to_be16_av(hash))
		return 0;

	if (tp->stealth.mode & TCP_STEALTH_MODE_AUTH &&
	    !(tp->stealth.mode & TCP_STEALTH_MODE_INTEGRITY_LEN) &&
	    isn == hash)
		return 0;

	return 1;
}
EXPORT_SYMBOL(tcp_stealth_do_auth);
#endif

#if IS_ENABLED(CONFIG_IPV6)
__u32 secure_tcpv6_sequence_number(const __be32 *saddr, const __be32 *daddr,
				   __be16 sport, __be16 dport)
{
	u32 secret[MD5_MESSAGE_BYTES / 4];
	u32 hash[MD5_DIGEST_WORDS];
	u32 i;

	net_secret_init();
	memcpy(hash, saddr, 16);
	for (i = 0; i < 4; i++)
		secret[i] = net_secret[i] + (__force u32)daddr[i];
	secret[4] = net_secret[4] +
		(((__force u16)sport << 16) + (__force u16)dport);
	for (i = 5; i < MD5_MESSAGE_BYTES / 4; i++)
		secret[i] = net_secret[i];

	md5_transform(hash, secret);

	return seq_scale(hash[0]);
}
EXPORT_SYMBOL(secure_tcpv6_sequence_number);

u32 secure_ipv6_port_ephemeral(const __be32 *saddr, const __be32 *daddr,
			       __be16 dport)
{
	u32 secret[MD5_MESSAGE_BYTES / 4];
	u32 hash[MD5_DIGEST_WORDS];
	u32 i;

	net_secret_init();
	memcpy(hash, saddr, 16);
	for (i = 0; i < 4; i++)
		secret[i] = net_secret[i] + (__force u32) daddr[i];
	secret[4] = net_secret[4] + (__force u32)dport;
	for (i = 5; i < MD5_MESSAGE_BYTES / 4; i++)
		secret[i] = net_secret[i];

	md5_transform(hash, secret);

	return hash[0];
}
EXPORT_SYMBOL(secure_ipv6_port_ephemeral);
#endif

#ifdef CONFIG_INET

__u32 secure_tcp_sequence_number(__be32 saddr, __be32 daddr,
				 __be16 sport, __be16 dport)
{
	u32 hash[MD5_DIGEST_WORDS];

	net_secret_init();
	hash[0] = (__force u32)saddr;
	hash[1] = (__force u32)daddr;
	hash[2] = ((__force u16)sport << 16) + (__force u16)dport;
	hash[3] = net_secret[15];

	md5_transform(hash, net_secret);

	return seq_scale(hash[0]);
}

u32 secure_ipv4_port_ephemeral(__be32 saddr, __be32 daddr, __be16 dport)
{
	u32 hash[MD5_DIGEST_WORDS];

	net_secret_init();
	hash[0] = (__force u32)saddr;
	hash[1] = (__force u32)daddr;
	hash[2] = (__force u32)dport ^ net_secret[14];
	hash[3] = net_secret[15];

	md5_transform(hash, net_secret);

	return hash[0];
}
EXPORT_SYMBOL_GPL(secure_ipv4_port_ephemeral);
#endif

#if IS_ENABLED(CONFIG_IP_DCCP)
u64 secure_dccp_sequence_number(__be32 saddr, __be32 daddr,
				__be16 sport, __be16 dport)
{
	u32 hash[MD5_DIGEST_WORDS];
	u64 seq;

	net_secret_init();
	hash[0] = (__force u32)saddr;
	hash[1] = (__force u32)daddr;
	hash[2] = ((__force u16)sport << 16) + (__force u16)dport;
	hash[3] = net_secret[15];

	md5_transform(hash, net_secret);

	seq = hash[0] | (((u64)hash[1]) << 32);
	seq += ktime_get_real_ns();
	seq &= (1ull << 48) - 1;

	return seq;
}
EXPORT_SYMBOL(secure_dccp_sequence_number);

#if IS_ENABLED(CONFIG_IPV6)
u64 secure_dccpv6_sequence_number(__be32 *saddr, __be32 *daddr,
				  __be16 sport, __be16 dport)
{
	u32 secret[MD5_MESSAGE_BYTES / 4];
	u32 hash[MD5_DIGEST_WORDS];
	u64 seq;
	u32 i;

	net_secret_init();
	memcpy(hash, saddr, 16);
	for (i = 0; i < 4; i++)
		secret[i] = net_secret[i] + (__force u32)daddr[i];
	secret[4] = net_secret[4] +
		(((__force u16)sport << 16) + (__force u16)dport);
	for (i = 5; i < MD5_MESSAGE_BYTES / 4; i++)
		secret[i] = net_secret[i];

	md5_transform(hash, secret);

	seq = hash[0] | (((u64)hash[1]) << 32);
	seq += ktime_get_real_ns();
	seq &= (1ull << 48) - 1;

	return seq;
}
EXPORT_SYMBOL(secure_dccpv6_sequence_number);
#endif
#endif
