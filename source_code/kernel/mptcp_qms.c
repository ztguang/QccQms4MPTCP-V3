/*
 1. passing QoE parameter to Android Kernel							in	tcp_v4_connect()		net/ipv4/tcp_ipv4.c
 2. set rwnd send to sender according to QoE & trigger (set in QCC)				in	__dev_queue_xmit()		net/core/dev.c
 3. set cwnd & ssthresh according to QoE 								in	QCC
 4. select subflow according to sort_rtt & & sort_cwnd & QoE					in	QMS
 */

/*
 *	MPTCP implementation - QoE-driven MPTCP Scheduler (QMS)
 *	QMS is a MPTCP Scheduler for MPTCP over wireless networks and is used in Android kernel.
 *
 *	QMS is based on the default scheduler of MPTCP.
 *
 *	Algorithm design: Tongguang Zhang <jsjoscpu@163.com>
 *
 *	Implementation: Tongguang Zhang <jsjoscpu@163.com>
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 */

/* MPTCP Scheduler module selector. Highly inspired by tcp_cong.c */

#include <linux/module.h>
#include <net/mptcp.h>
#include <trace/events/tcp.h>

struct qmssched_priv {
	u32	last_rbuf_opti;
};

static struct qmssched_priv *qmssched_get_priv(const struct tcp_sock *tp)
{
	return (struct qmssched_priv *)&tp->mptcp->mptcp_sched[0];
}

static bool mptcp_is_temp_unavailable(struct sock *sk,
				      const struct sk_buff *skb,
				      bool zero_wnd_test)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	unsigned int mss_now, space, in_flight;

	if (inet_csk(sk)->icsk_ca_state == TCP_CA_Loss) {
		/* If SACK is disabled, and we got a loss, TCP does not exit
		 * the loss-state until something above high_seq has been
		 * acked. (see tcp_try_undo_recovery)
		 *
		 * high_seq is the snd_nxt at the moment of the RTO. As soon
		 * as we have an RTO, we won't push data on the subflow.
		 * Thus, snd_una can never go beyond high_seq.
		 */
		if (!tcp_is_reno(tp))
			return true;
		else if (tp->snd_una != tp->high_seq)
			return true;
	}

	if (!tp->mptcp->fully_established) {
		/* Make sure that we send in-order data */
		if (skb && tp->mptcp->second_packet &&
		    tp->mptcp->last_end_data_seq != TCP_SKB_CB(skb)->seq)
			return true;
	}

	in_flight = tcp_packets_in_flight(tp);
	/* Not even a single spot in the cwnd */
	if (in_flight >= tp->snd_cwnd)
		return true;

	mss_now = tcp_current_mss(sk);

	/* Now, check if what is queued in the subflow's send-queue
	 * already fills the cwnd.
	 */
	space = (tp->snd_cwnd - in_flight) * mss_now;

	if (tp->write_seq - tp->snd_nxt >= space)
		return true;

	if (zero_wnd_test && !before(tp->write_seq, tcp_wnd_end(tp)))
		return true;

	/* Don't send on this subflow if we bypass the allowed send-window at
	 * the per-subflow level. Similar to tcp_snd_wnd_test, but manually
	 * calculated end_seq (because here at this point end_seq is still at
	 * the meta-level).
	 */
	if (skb && zero_wnd_test &&
	    after(tp->write_seq + min(skb->len, mss_now), tcp_wnd_end(tp)))
		return true;

	return false;
}

/* Are we not allowed to reinject this skb on tp? */
static int mptcp_dont_reinject_skb(const struct tcp_sock *tp, const struct sk_buff *skb)
{
	/* If the skb has already been enqueued in this sk, try to find
	 * another one.
	 */
	return skb &&
		/* Has the skb already been enqueued into this subsocket? */
		mptcp_pi_to_flag(tp->mptcp->path_index) & TCP_SKB_CB(skb)->path_mask;
}



/* Generic function to iterate over used and unused subflows and to select the
 * best one
 */
static struct sock
*get_subflow_from_selectors(struct mptcp_cb *mpcb, struct sk_buff *skb,
			    bool (*selector)(const struct tcp_sock *),
			    bool zero_wnd_test, bool *force)
{
	struct sock *bestsk = NULL;
	u32 min_srtt = 0xffffffff;
	bool found_unused = false;
	bool found_unused_una = false;
	struct mptcp_tcp_sock *mptcp;

	mptcp_for_each_sub(mpcb, mptcp) {
		struct sock *sk = mptcp_to_sock(mptcp);
		struct tcp_sock *tp = tcp_sk(sk);
		bool unused = false;

		if(tp->qccqms.trigger == 1 && 
				((tp->qccqms.qoe==1 && tp->qccqms.nif == 1) || 			// qoe==1, only use WIFI
				 (tp->qccqms.qoe==2 && tp->qccqms.nif == 2)) )			// qoe==2, only use 4G or eth
			continue;

		/* First, we choose only the wanted sks */
		if (!(*selector)(tp))
			continue;

		if (!mptcp_dont_reinject_skb(tp, skb))
			unused = true;
		else if (found_unused)
			/* If a unused sk was found previously, we continue -
			 * no need to check used sks anymore.
			 */
			continue;

		if (mptcp_is_def_unavailable(sk))				// ztg, from mptcp_sched.c
			continue;

		if (mptcp_is_temp_unavailable(sk, skb, zero_wnd_test)) {
			if (unused)
				found_unused_una = true;
			continue;
		}

		if (unused) {
			if (!found_unused) {
				/* It's the first time we encounter an unused
				 * sk - thus we reset the bestsk (which might
				 * have been set to a used sk).
				 */
				min_srtt = 0xffffffff;
				bestsk = NULL;
			}
			found_unused = true;
		}

		if( (tp->qccqms.trigger == 1 && tp->qccqms.qoe==1 && tp->qccqms.nif == 2 && (tp->qccqms.ID == 1 || tp->qccqms.ID == 3) ) ||
		    (tp->qccqms.trigger == 1 && tp->qccqms.qoe==2 && tp->qccqms.nif == 1 && (tp->qccqms.ID == 1 || tp->qccqms.ID == 3) ) ||
		    (tp->qccqms.trigger == 1 && tp->qccqms.qoe==3 && ( tp->qccqms.sort_cwnd==1 && (tp->qccqms.ID == 1 || tp->qccqms.ID == 3) ) && 
										(tp->qccqms.num_big_pkts > 2*tp->qccqms.num_small_pkts) ) ||
		    (tp->qccqms.trigger == 1 && tp->qccqms.qoe==3 && ( tp->qccqms.sort_rtt==1 && (tp->qccqms.ID == 1 || tp->qccqms.ID == 3) ) && 
										(tp->qccqms.num_small_pkts > 2*tp->qccqms.num_big_pkts) ) ||
		    (tp->qccqms.trigger == 1 && tp->qccqms.qoe==7 && ( tp->qccqms.sort_cwnd==1 && (tp->qccqms.ID == 1 || tp->qccqms.ID == 3) ) ) ||
		    (tp->qccqms.trigger == 1 && tp->qccqms.qoe==11 && ( tp->qccqms.sort_rtt==1 && (tp->qccqms.ID == 1 || tp->qccqms.ID == 3) ) ) ) {
			bestsk = sk;
		} else if (tp->srtt_us < min_srtt) {
			min_srtt = tp->srtt_us;
			bestsk = sk;
		}

	}

	if (bestsk) {
		/* The force variable is used to mark the returned sk as
		 * previously used or not-used.
		 */
		if (found_unused)
			*force = true;
		else
			*force = false;
	} else {
		/* The force variable is used to mark if there are temporally
		 * unavailable not-used sks.
		 */
		if (found_unused_una)
			*force = true;
		else
			*force = false;
	}

	return bestsk;
}



/* This is the scheduler. This function decides on which flow to send
 * a given MSS. If all subflows are found to be busy, NULL is returned
 * The flow is selected based on the shortest RTT.
 * If all paths have full cong windows, we simply return NULL.
 *
 * Additionally, this function is aware of the backup-subflows.
 */
static struct sock *qms_get_available_subflow(struct sock *meta_sk, struct sk_buff *skb,
				   bool zero_wnd_test)
{
	struct mptcp_cb *mpcb = tcp_sk(meta_sk)->mpcb;
	struct sock *sk;
	bool looping = false, force;

	/* Answer data_fin on same subflow!!! */
	if (meta_sk->sk_shutdown & RCV_SHUTDOWN &&
	    skb && mptcp_is_data_fin(skb)) {
		struct mptcp_tcp_sock *mptcp;

		mptcp_for_each_sub(mpcb, mptcp) {
			sk = mptcp_to_sock(mptcp);

			if (tcp_sk(sk)->mptcp->path_index == mpcb->dfin_path_index &&
			    mptcp_is_available(sk, skb, zero_wnd_test))				// ztg, from mptcp_sched.c
				return sk;
		}
	}

	/* Find the best subflow */
restart:

	sk = get_subflow_from_selectors(mpcb, skb, &subflow_is_active,				// ztg, subflow_is_active from mptcp_sched.c
					zero_wnd_test, &force);
	if (force)
		/* one unused active sk or one NULL sk when there is at least
		 * one temporally unavailable unused active sk
		 */
		return sk;

	sk = get_subflow_from_selectors(mpcb, skb, &subflow_is_backup,				// ztg, subflow_is_backup from mptcp_sched.c
					zero_wnd_test, &force);
	if (!force && skb) {
		/* one used backup sk or one NULL sk where there is no one
		 * temporally unavailable unused backup sk
		 *
		 * the skb passed through all the available active and backups
		 * sks, so clean the path mask
		 */
		TCP_SKB_CB(skb)->path_mask = 0;

		if (!looping) {
			looping = true;
			goto restart;
		}
	}
	return sk;
}


/* Returns the next segment to be sent from the mptcp meta-queue.
 * (chooses the reinject queue if any segment is waiting in it, otherwise,
 * chooses the normal write queue).
 * Sets *@reinject to 1 if the returned segment comes from the
 * reinject queue. Sets it to 0 if it is the regular send-head of the meta-sk,
 * and sets it to -1 if it is a meta-level retransmission to optimize the
 * receive-buffer.
 */
static struct sk_buff *__qms_mptcp_next_segment(struct sock *meta_sk, int *reinject)
{
	const struct mptcp_cb *mpcb = tcp_sk(meta_sk)->mpcb;
	struct sk_buff *skb = NULL;

	*reinject = 0;

	/* If we are in fallback-mode, just take from the meta-send-queue */
	if (mpcb->infinite_mapping_snd || mpcb->send_infinite_mapping)
		return tcp_send_head(meta_sk);

	skb = skb_peek(&mpcb->reinject_queue);

	if (skb) {
		*reinject = 1;
	} else {
		skb = tcp_send_head(meta_sk);

		if (!skb && meta_sk->sk_socket &&
		    test_bit(SOCK_NOSPACE, &meta_sk->sk_socket->flags) &&
		    sk_stream_wspace(meta_sk) < sk_stream_min_wspace(meta_sk)) {
			struct sock *subsk;

			/* meta is send buffer limited */
			tcp_chrono_start(meta_sk, TCP_CHRONO_SNDBUF_LIMITED);

			subsk = qms_get_available_subflow(meta_sk, NULL, false);

			if (!subsk)
				return NULL;

			skb = mptcp_rcv_buf_optimization(subsk, 0);
			if (skb)
				*reinject = -1;
			else
				tcp_chrono_start(subsk,
						 TCP_CHRONO_SNDBUF_LIMITED);
		}
	}
	return skb;
}

static struct sk_buff *qms_mptcp_next_segment(struct sock *meta_sk,
					  int *reinject,
					  struct sock **subsk,
					  unsigned int *limit)
{
	struct sk_buff *skb = __qms_mptcp_next_segment(meta_sk, reinject);
	unsigned int mss_now;
	u32 max_len, gso_max_segs, max_segs, max_tso_segs, window;
	struct tcp_sock *subtp;
	int queued;

	/* As we set it, we have to reset it as well. */
	*limit = 0;

	if (!skb)
		return NULL;

	*subsk = qms_get_available_subflow(meta_sk, skb, false);

	if (!*subsk)
		return NULL;

	subtp = tcp_sk(*subsk);
	mss_now = tcp_current_mss(*subsk);

	if (!*reinject && unlikely(!tcp_snd_wnd_test(tcp_sk(meta_sk), skb, mss_now))) {
		/* an active flow is selected, but segment will not be sent due
		 * to no more space in send window
		 * this means the meta is receive window limited
		 * the subflow might also be, if we have nothing to reinject
		 */
		tcp_chrono_start(meta_sk, TCP_CHRONO_RWND_LIMITED);
		skb = mptcp_rcv_buf_optimization(*subsk, 1);
		if (skb)
			*reinject = -1;
		else
			return NULL;
	}

	if (!*reinject) {
		/* this will stop any other chronos on the meta */
		tcp_chrono_start(meta_sk, TCP_CHRONO_BUSY);
	}

	/* No splitting required, as we will only send one single segment */
	if (skb->len <= mss_now)
		return skb;

	max_tso_segs = tcp_tso_segs(*subsk, tcp_current_mss(*subsk));
	queued = mptcp_subflow_queued(*subsk, max_tso_segs);

	/* this condition should already have been established in
	 * mptcp_is_temp_unavailable when selecting available flows
	 */
	WARN_ONCE(subtp->snd_cwnd <= queued, "Selected subflow no cwnd room");

	gso_max_segs = (*subsk)->sk_gso_max_segs;
	if (!gso_max_segs) /* No gso supported on the subflow's NIC */
		gso_max_segs = 1;

	max_segs = min_t(unsigned int, subtp->snd_cwnd - queued, gso_max_segs);
	if (!max_segs)
		return NULL;

	/* if there is room for a segment, schedule up to a complete TSO
	 * segment to avoid TSO splitting. Even if it is more than allowed by
	 * the congestion window.
	 */
	max_segs = max_t(unsigned int, max_tso_segs, max_segs);

	max_len = min(mss_now * max_segs, skb->len);

	window = tcp_wnd_end(subtp) - subtp->write_seq;

	/* max_len now also respects the announced receive-window */
	max_len = min(max_len, window);

	*limit = max_len;

	return skb;
}
//------------------------------------------------------------------------------ // 20230317


static void qmssched_init(struct sock *sk)
{
	struct qmssched_priv *qms_p = qmssched_get_priv(tcp_sk(sk));

	qms_p->last_rbuf_opti = tcp_jiffies32;		// 4.19
//	qms_p->last_rbuf_opti = tcp_time_stamp;		// 4.9
}

static struct mptcp_sched_ops mptcp_sched_qms = {
	.get_subflow = qms_get_available_subflow,
	.next_segment = qms_mptcp_next_segment,			// 20230317
	.init = qmssched_init,
	.name = "qms",
	.owner = THIS_MODULE,
};

static int __init qms_register(void)
{
	BUILD_BUG_ON(sizeof(struct qmssched_priv) > MPTCP_SCHED_SIZE);

	if (mptcp_register_scheduler(&mptcp_sched_qms))
		return -1;

	return 0;
}

static void qms_unregister(void)
{
	mptcp_unregister_scheduler(&mptcp_sched_qms);
}

module_init(qms_register);
module_exit(qms_unregister);

MODULE_AUTHOR("Tongguang Zhang");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("QMS (QoE-Driven MPTCP Scheduler) MPTCP");		//MODULE_DESCRIPTION("min_rtt");
MODULE_VERSION("0.1");



