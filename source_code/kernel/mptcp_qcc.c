#include <linux/mm.h>
#include <linux/module.h>
#include <linux/math64.h>
#include <net/tcp.h>
#include <net/mptcp.h>

#define BICTCP_BETA_SCALE    1024	/* Scale factor beta calculation
					 * max_cwnd = snd_cwnd * beta
					 */
#define	BICTCP_HZ		10	/* BIC HZ 2^10 = 1024 */

/* Two methods of hybrid slow start */
#define HYSTART_ACK_TRAIN	0x1
#define HYSTART_DELAY		0x2

/* Number of delay samples for detecting the increase of delay */
#define HYSTART_MIN_SAMPLES	8
#define HYSTART_DELAY_MIN	(4U<<3)		/* (2U<<3)	Delay increase threshold最小为16ms */
#define HYSTART_DELAY_MAX	(16U<<3)		/* Delay increase threshold最大为128ms */
#define HYSTART_DELAY_THRESH(x)	clamp(x, HYSTART_DELAY_MIN, HYSTART_DELAY_MAX)

static int fast_convergence __read_mostly = 1;		/* 快速收敛 */
static int beta __read_mostly = 717;	/* = 717/1024 (BICTCP_BETA_SCALE) */
static int initial_ssthresh __read_mostly;			/* 初始慢启动阈值 */
static int bic_scale __read_mostly = 41;
static int tcp_friendliness __read_mostly = 1;		/* 友好性 */

static int hystart __read_mostly = 1;			/* HyStart开关 */
static int hystart_detect __read_mostly = HYSTART_ACK_TRAIN | HYSTART_DELAY;
static int hystart_low_window __read_mostly = 16;		/* 除非cwnd超过了这个值，才能使用HyStart */
static int hystart_ack_delta __read_mostly = 2;

static u32 cube_rtt_scale __read_mostly;
static u32 beta_scale __read_mostly;
static u64 cube_factor __read_mostly;

/* Note parameters that are used for precomputing scale factors are read-only */
module_param(fast_convergence, int, 0644);
MODULE_PARM_DESC(fast_convergence, "turn on/off fast convergence");
module_param(beta, int, 0644);
MODULE_PARM_DESC(beta, "beta for multiplicative increase");
module_param(initial_ssthresh, int, 0644);
MODULE_PARM_DESC(initial_ssthresh, "initial value of slow start threshold");
module_param(bic_scale, int, 0444);
MODULE_PARM_DESC(bic_scale, "scale (scaled by 1024) value for bic function (bic_scale/1024)");	//bic_scale就是paper中三次方系数C的1024倍缩放值
module_param(tcp_friendliness, int, 0644);
MODULE_PARM_DESC(tcp_friendliness, "turn on/off tcp friendliness");
module_param(hystart, int, 0644);
MODULE_PARM_DESC(hystart, "turn on/off hybrid slow start algorithm");
module_param(hystart_detect, int, 0644);
MODULE_PARM_DESC(hystart_detect, "hybrid slow start detection mechanisms"
		 " 1: packet-train 2: delay 3: both packet-train and delay");
module_param(hystart_low_window, int, 0644);
MODULE_PARM_DESC(hystart_low_window, "lower bound cwnd for hybrid slow start");
module_param(hystart_ack_delta, int, 0644);
MODULE_PARM_DESC(hystart_ack_delta, "spacing between ack's indicating train (msecs)");



/* BIC TCP Parameters */
struct mptcp_qcc {				// struct mptcp_qcc 共 64 个字节。由于 64 < 104，因此，不需要修改 下面 inet_connection_sock.h	20230313
						// include/net/inet_connection_sock.h
						//	u64			  icsk_ca_priv[104 / sizeof(u64)];
						//#define ICSK_CA_PRIV_SIZE      (13 * sizeof(u64))

	u32	beg_snd_nxt;		// right edge during last RTT

	u32	cnt;			/* increase cwnd by 1 after ACKs */		// 用于控制 snd_cwnd 增长速度
	u32	last_max_cwnd;		/* last maximum snd_cwnd */
					//两个重要的count值:
					//第一个是tcp_sock->snd_cwnd_cnt，表示在当前的拥塞窗口中已经发送(经过对方ack包确认)的数据段的个数，
					//而第二个是bictcp->cnt，它是cubic拥塞算法的核心，主要用来控制在拥塞避免状态的时候，什么时候才能增大拥塞窗口，
					//具体实现是通过比较 cnt 和 snd_cwnd_cnt，来决定是否增大拥塞窗口，


//	u32	loss_cwnd;	/* congestion window at last loss */		// 应该无用
	u32	last_cwnd;	/* the last snd_cwnd */
	u32	last_time;	/* time when updated last_cwnd */
	u32	bic_origin_point;/* origin point of bic function */		/* 即新的 Wmax，取 Wlast_max 和 snd_cwnd 大者 */
	u32	bic_K;		/* time to origin point
				   from the beginning of the current epoch */	/* 即新Wmax所对应的时间点t，W(bic_K) = Wmax */
	u32	delay_min;	/* min delay (msec << 3) */				/* 是最小RTT */
	u32	epoch_start;	/* beginning of an epoch */
	u32	ack_cnt;	/* number of acks */
	u32	tcp_cwnd;	/* estimated tcp cwnd */				/* 按照 Reno 算法计算得的cwnd */

//	u32	RTT[8];		// The lastest 8 RTTs are stored in array Arr[6], used to calculate ID (Increase Decrease)
	u32	num_pkts_acked;	// used to calculate ID (Increase Decrease)  	20230318

	u8	nouse;

	u8	sample_cnt;	/* number of samples to decide curr_rtt */		/* 第几个sample */
	u8	found;		/* the exit point is found? */
	u32	qcc_roundStart;	/* beginning of each round */			/* 针对每个RTT */
	u32	end_seq;	/* end_seq of the round */				/* 用来标识每个RTT */
	u32	last_ack;	/* last time when the ACK spacing is close */
	u32	curr_rtt;	/* the minimum rtt of current round */		/* 由sampe中最小的决定 */
};


static inline void mptcp_qcc_reset(struct mptcp_qcc *qcc, struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	qcc->cnt = 0;
	qcc->last_max_cwnd = 0;
//	qcc->loss_cwnd = 0;
	qcc->last_cwnd = 0;
	qcc->last_time = 0;
	qcc->bic_origin_point = 0;
	qcc->bic_K = 0;
	qcc->delay_min = 0;
	qcc->epoch_start = 0;
	qcc->ack_cnt = 0;
	qcc->tcp_cwnd = 0;
	qcc->found = 0;

	qcc->beg_snd_nxt = tp->snd_nxt;
	qcc->num_pkts_acked = 0;

	tp->qccqms.RTT[0] = tp->qccqms.RTT[1] = tp->qccqms.RTT[2] = tp->qccqms.RTT[3] = tp->qccqms.RTT[4] = tp->qccqms.RTT[5] = tp->qccqms.RTT[6] = tp->qccqms.RTT[7] = 0;
	tp->qccqms.cntRTT = 0;
	tp->qccqms.cumRTT = 0;
	tp->qccqms.aver_rtt = 0x7fffffff;	// ztg add	20230318

//	tp->qccqms.nif_sends = 0;	//20230317
	tp->qccqms.hy_low_window = hystart_low_window;

	tp->qccqms.nif = 0;	//20230316	// nif = 1 // in oneplus8t-Android-arm, 4G   // in VB-Android-x86, VB 中 eth1 实际是有线		20230307
						// nif = 2 // in oneplus8t-Android-arm, WIFI // in VB-Android-x86, VB 中 eth2 实际是无线 WIFI
}

static inline u32 bictcp_clock(void)
{
#if HZ < 1000
	return ktime_to_ms(ktime_get_real());
#else
	return jiffies_to_msecs(jiffies);
#endif
}


static inline void bictcp_hystart_reset(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct mptcp_qcc *qcc = inet_csk_ca(sk);

	qcc->qcc_roundStart = qcc->last_ack = bictcp_clock();
	qcc->end_seq = tp->snd_nxt;
	qcc->curr_rtt = 0;
	qcc->sample_cnt = 0;
}


static void mptcp_qcc_init(struct sock *sk)
{
	struct mptcp_qcc *qcc = inet_csk_ca(sk);

	struct tcp_sock *tp = tcp_sk(sk);
	mptcp_qcc_reset(qcc, sk);

	if (hystart)
		bictcp_hystart_reset(sk);

	if (!hystart && initial_ssthresh)
		tcp_sk(sk)->snd_ssthresh = initial_ssthresh;


	qcc->beg_snd_nxt = tp->snd_nxt;
	qcc->num_pkts_acked = 0;

	tp->qccqms.RTT[0] = tp->qccqms.RTT[1] = tp->qccqms.RTT[2] = tp->qccqms.RTT[3] = tp->qccqms.RTT[4] = tp->qccqms.RTT[5] = tp->qccqms.RTT[6] = tp->qccqms.RTT[7] = 0;

	tp->qccqms.cntRTT = 0;
	tp->qccqms.cumRTT = 0;

//	tp->qccqms.nif_sends = 0;		//20230317
	tp->qccqms.hy_low_window = hystart_low_window;

	tp->qccqms.sort_rtt = 0;
	tp->qccqms.sort_cwnd = 0;
	tp->qccqms.sort_bdp = 0;

	tp->qccqms.tri_cond = 8;		// the trigger condition for QoE, The initial value is 8, refer to RTT[8]
	tp->qccqms.trigger = 0;			// Triggered after 8 ack packets received
	tp->qccqms.nif = 0;			// nif = 1 // in oneplus8t-Android-arm, 4G   // in VB-Android-x86, VB 中 eth1 实际是有线		20230307
						// nif = 2 // in oneplus8t-Android-arm, WIFI // in VB-Android-x86, VB 中 eth2 实际是无线 WIFI
	tp->qccqms.minRTT = 0x7fffffff;
//	tp->qccqms.maxRTT = 0;
//	tp->qccqms.baseRTT = 0x7fffffff;

//	tp->qccqms.bdp = 0;			// ztg add	20211207	20230313
	tp->qccqms.aver_rtt = 0x7fffffff;	// ztg add	20230318

	tp->qccqms.ID = 0;			// ztg add	20230305

	tp->qccqms.num_big_pkts = 0;		// ztg add	20230307
	tp->qccqms.num_small_pkts = 0;		// ztg add	20230307

	tp->snd_ssthresh = TCP_INFINITE_SSTHRESH;	//#define TCP_INFINITE_SSTHRESH	0x7fffffff
}


static void bictcp_cwnd_event(struct sock *sk, enum tcp_ca_event event)
{
	if (event == CA_EVENT_TX_START) {
		struct mptcp_qcc *qcc = inet_csk_ca(sk);
		u32 now = tcp_jiffies32;
		s32 delta;

		delta = now - tcp_sk(sk)->lsndtime;

		/* We were application limited (idle) for a while.
		 * Shift epoch_start to keep cwnd growth to cubic curve.
		 */
		if (qcc->epoch_start && delta > 0) {
			qcc->epoch_start += delta;
			if (after(qcc->epoch_start, now))
				qcc->epoch_start = now;
		}
		return;
	}
}

static u32 cubic_root(u64 a)
{
	u32 x, b, shift;
	/*
	 * cbrt(x) MSB values for x MSB values in [0..63].
	 * Precomputed then refined by hand - Willy Tarreau
	 *
	 * For x in [0..63],
	 *   v = cbrt(x << 18) - 1
	 *   cbrt(x) = (v[x] + 10) >> 6
	 */
	static const u8 v[] = {
		/* 0x00 */    0,   54,   54,   54,  118,  118,  118,  118,
		/* 0x08 */  123,  129,  134,  138,  143,  147,  151,  156,
		/* 0x10 */  157,  161,  164,  168,  170,  173,  176,  179,
		/* 0x18 */  181,  185,  187,  190,  192,  194,  197,  199,
		/* 0x20 */  200,  202,  204,  206,  209,  211,  213,  215,
		/* 0x28 */  217,  219,  221,  222,  224,  225,  227,  229,
		/* 0x30 */  231,  232,  234,  236,  237,  239,  240,  242,
		/* 0x38 */  244,  245,  246,  248,  250,  251,  252,  254,
	};

	b = fls64(a);
	if (b < 7) {
		/* a in [0..63] */
		return ((u32)v[(u32)a] + 35) >> 6;
	}

	b = ((b * 84) >> 8) - 1;
	shift = (a >> (b * 3));

	x = ((u32)(((u32)v[shift] + 10) << b)) >> 6;

	/*
	 * Newton-Raphson iteration
	 *                         2
	 * x    = ( 2 * x  +  a / x  ) / 3
	 *  k+1          k         k
	 */
	x = (2 * x + (u32)div64_u64(a, (u64)x * (u64)(x - 1)));
	x = ((x * 341) >> 10);
	return x;
}



static inline void mptcp_qcc_update(struct sock *sk, struct mptcp_qcc *qcc, u32 cwnd, u32 acked)
{
	struct tcp_sock *tp = tcp_sk(sk);

	u32 delta, bic_target, max_cnt;	/* delta是cwnd差，bic_target是预测值，t为预测时间 */
	u64 offs, t;				/* 时间差，offs = | t - K | */

	qcc->ack_cnt += acked;	/* count the number of ACKed packets */

	if (qcc->last_cwnd == cwnd &&
	    (s32)(tcp_jiffies32 - qcc->last_time) <= HZ / 32)
		return;

	/* The CUBIC function can update qcc->cnt at most once per jiffy.
	 * On all cwnd reduction events, qcc->epoch_start is set to 0,
	 * which will force a recalculation of qcc->cnt.
	 */
	if (qcc->epoch_start && tcp_jiffies32 == qcc->last_time)
		goto tcp_friendliness;

	qcc->last_cwnd = cwnd;
	qcc->last_time = tcp_jiffies32;

	/*丢包后 一个新的时段 */
	if (qcc->epoch_start == 0) {
		qcc->epoch_start = tcp_jiffies32;	/* record beginning */
		qcc->ack_cnt = acked;			/* start counting */
		qcc->tcp_cwnd = cwnd;			/* syn with cubic */

		if (qcc->last_max_cwnd <= cwnd) {
			qcc->bic_K = 0;
			qcc->bic_origin_point = cwnd;
		} else {
			/* Compute new K based on
			 * (wmax-cwnd) * (srtt>>3 / HZ) / c * 2^(3*bictcp_HZ)
			 */
					/* Compute new K 
					 * cube_factor = 2^40 / (41*10) = 2^30 / ( C*10) = 2^30 / 0.4
					 * bic_K本来单位为秒，转成单位为 1 / 1024秒。
					 */
			qcc->bic_K = cubic_root(cube_factor
					       * (qcc->last_max_cwnd - cwnd));
			qcc->bic_origin_point = qcc->last_max_cwnd;
		}
	}

	/* cubic function - calc*/
	/* calculate c * time^3 / rtt,
	 *  while considering overflow in calculation of time^3
	 * (so time^3 is done by using 64 bit)
	 * and without the support of division of 64bit numbers
	 * (so all divisions are done by using 32 bit)
	 *  also NOTE the unit of those veriables
	 *	  time  = (t - K) / 2^bictcp_HZ
	 *	  c = bic_scale >> 10
	 * rtt  = (srtt >> 3) / HZ
	 * !!! The following code does not have overflow problems,
	 * if the cwnd < 1 million packets !!!
	 */

	t = (s32)(tcp_jiffies32 - qcc->epoch_start);
	t += msecs_to_jiffies(qcc->delay_min >> 3);
	/* change the unit from HZ to bictcp_HZ */
	t <<= BICTCP_HZ;
	do_div(t, HZ);

	if (t < qcc->bic_K)		/* t - K */		/* 还未达到Wmax */
		offs = qcc->bic_K - t;
	else
		offs = t - qcc->bic_K;			/* 此时已经超过Wmax */

	/* c/rtt * (t-K)^3 */
	delta = (cube_rtt_scale * offs * offs * offs) >> (10+3*BICTCP_HZ);
	/* 计算bic_target，即预测cwnd */
	if (t < qcc->bic_K)                            /* below origin*/
		bic_target = qcc->bic_origin_point - delta;
	else                                          /* above origin*/
		bic_target = qcc->bic_origin_point + delta;

	/* cubic function - calc bictcp_cnt*/
	if (bic_target > cwnd) {
		qcc->cnt = cwnd / (bic_target - cwnd);		/* 相差越多，增长越快，这就是函数形状由来 */
	} else {
		qcc->cnt = 100 * cwnd;              /* very small increment*/		/* 目前cwnd已经超出预期了，应该降速 */
	}

	/*
	 * The initial growth of cubic function may be too conservative
	 * when the available bandwidth is still unknown.
	 */
	if (qcc->last_max_cwnd == 0 && qcc->cnt > 20)
		qcc->cnt = 20;	/* increase cwnd 5% per RTT */

tcp_friendliness:
	/* TCP Friendly */
	if (tcp_friendliness) {
		u32 scale = beta_scale;

		delta = (cwnd * scale) >> 3;		/* delta 代表多少 ACK 可使 tcp_cwnd++ */
		while (qcc->ack_cnt > delta) {		/* update tcp cwnd */
			qcc->ack_cnt -= delta;
			qcc->tcp_cwnd++;
		}

		if (qcc->tcp_cwnd > cwnd) {	/* if bic is slower than tcp */
			delta = qcc->tcp_cwnd - cwnd;
			max_cnt = cwnd / delta;

			if (tp->qccqms.trigger == 1) {
				if (qcc->cnt < max_cnt) qcc->cnt = max_cnt;
			} else {
				if (qcc->cnt > max_cnt) qcc->cnt = max_cnt;
			}
		}
	}

	/* The maximum rate of cwnd increase CUBIC allows is 1 packet per
	 * 2 packets ACKed, meaning cwnd grows at 1.5x per RTT.
	 */
	qcc->cnt = max(qcc->cnt, 2U);
}

static void mptcp_qcc_calculate(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	if (1) {
		// get the subflow that has min rrt, get the subflow that has max cwnd (free_cwnd)
		u32 min_rrt = 0xffffffff;
		u8  min_rrt_subfid = 0xff;
		u32 max_cwnd = 0, free_cwnd;
		u8  max_cwnd_subfid = 0xff;
		//u64 max_bdp = 0;
		//u8  max_bdp_subfid = 0xff;
		struct mptcp_tcp_sock *mptcp;

		mptcp_for_each_sub(tp->mpcb, mptcp) {
			struct sock *sub_sk = mptcp_to_sock(mptcp);
			struct tcp_sock *sub_tp = tcp_sk(sub_sk);
			if (sub_tp->qccqms.cntRTT) sub_tp->qccqms.aver_rtt = sub_tp->qccqms.cumRTT / sub_tp->qccqms.cntRTT;
	
			if(min_rrt > sub_tp->qccqms.aver_rtt) {
				min_rrt = sub_tp->qccqms.aver_rtt;
				min_rrt_subfid = sub_tp->mptcp->path_index;
			}

			//if(max_cwnd < sub_tp->snd_cwnd) {
			//	max_cwnd = sub_tp->snd_cwnd;
			//	max_cwnd_subfid = sub_tp->mptcp->path_index;
			//}
			free_cwnd = sub_tp->snd_cwnd - tcp_packets_in_flight(sub_tp);
			if(max_cwnd < free_cwnd) {
				max_cwnd = free_cwnd;
				max_cwnd_subfid = sub_tp->mptcp->path_index;
			}

			//sub_tp->qccqms.bdp = sub_tp->qccqms.aver_rtt * qcc->last_max_cwnd;
			//if(max_bdp < sub_tp->qccqms.bdp) {
			//	max_bdp = sub_tp->qccqms.bdp;
			//	max_bdp_subfid = sub_tp->mptcp->path_index;
			//}

			sub_tp->qccqms.cntRTT = 0;
			sub_tp->qccqms.cumRTT = 0;
			sub_tp->qccqms.aver_rtt = 0x7fffffff;	// ztg add	20230318
		}

		mptcp_for_each_sub(tp->mpcb, mptcp) {
			struct sock *sub_sk = mptcp_to_sock(mptcp);
			struct tcp_sock *sub_tp = tcp_sk(sub_sk);
			if (sub_tp->mptcp->path_index == min_rrt_subfid) sub_tp->qccqms.sort_rtt = 1;	// get the subflow that has min rrt
			else sub_tp->qccqms.sort_rtt = 2;
			if (sub_tp->mptcp->path_index == max_cwnd_subfid) sub_tp->qccqms.sort_cwnd = 1;	// get the subflow that has max cwnd
			else sub_tp->qccqms.sort_cwnd = 2;
			//if (sub_tp->mptcp->path_index == max_bdp_subfid) sub_tp->qccqms.sort_bdp = 1;	// get the subflow that has max bdp
			//else sub_tp->qccqms.sort_bdp = 2;
		}
	}

	tp->qccqms.num_big_pkts = 0;	//used in net/core/dev.c and net/mptcp/mptcp_qms.c and net/mptcp/mptcp_qcc.c
	tp->qccqms.num_small_pkts = 0;	//num_big_pkts 和 num_small_pkts 在 net/core/dev.c 中 根据包的大小 逐步赠一

	tp->qccqms.minRTT = 0x7fffffff;
	//tp->qccqms.maxRTT = 0;
}


static inline void mptcp_qcc_avoid_ai(struct sock *sk, struct tcp_sock *tp, u32 w, u32 acked, const struct rate_sample *rs)	// come from tcp_cong.c
{
	/* If credits accumulated at a higher w, apply them gently now. */
	if (tp->snd_cwnd_cnt >= w) {
		tp->snd_cwnd_cnt = 0;
		if (tp->qccqms.trigger == 1) {
			if (tp->qccqms.ID==1) tp->snd_cwnd += 4;			// RTT Basically Unchanged
			else if (tp->qccqms.ID==2) tp->snd_cwnd += 1;			// RTT Increase
			else if (tp->qccqms.ID==3) tp->snd_cwnd += 3;			// RTT Decrease
			else tp->snd_cwnd += 2;
		} else
			tp->snd_cwnd++;
	}

	tp->snd_cwnd_cnt += acked;			// 进入拥塞避免阶段，每收到一个ACK报文，cwnd_cnt++
	if (tp->snd_cwnd_cnt >= w) {
		u32 delta = tp->snd_cwnd_cnt / w;

		tp->snd_cwnd_cnt -= delta * w;
		tp->snd_cwnd += delta;
	}
	tp->snd_cwnd = min(tp->snd_cwnd, tp->snd_cwnd_clamp);
}


static void mptcp_qcc_cong_avoid(struct sock *sk, u32 ack, u32 acked, const struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct mptcp_qcc *qcc = inet_csk_ca(sk);

	if (!tcp_is_cwnd_limited(sk))
		return;

	if (tcp_in_slow_start(tp)) {
		acked = tcp_slow_start(tp, acked);
		if (!acked)
			return;
	}

	if (after(ack, qcc->beg_snd_nxt)) {
		qcc->beg_snd_nxt = tp->snd_nxt;
		mptcp_qcc_calculate(sk);
	}
	mptcp_qcc_update(sk, qcc, tp->snd_cwnd, acked);
	mptcp_qcc_avoid_ai(sk, tp, qcc->cnt, acked, rs);
}


static u32 mptcp_qcc_ssthresh(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	struct mptcp_qcc *qcc = inet_csk_ca(sk);

	qcc->epoch_start = 0;	/* end of epoch */

	/* Wmax and fast convergence */
	if (tp->snd_cwnd < qcc->last_max_cwnd && fast_convergence)
		qcc->last_max_cwnd = (tp->snd_cwnd * (BICTCP_BETA_SCALE + beta))
			/ (2 * BICTCP_BETA_SCALE);
	else
		qcc->last_max_cwnd = tp->snd_cwnd;

	if (tp->qccqms.trigger == 1) {	//ztg 20230318
		if (tp->qccqms.ID==1) return max(tp->snd_cwnd*5/4, 2U);				// RTT Basically Unchanged
		else if (tp->qccqms.ID==2) return max(tp->snd_cwnd*3/4, 2U);			// RTT Increase
		else if (tp->qccqms.ID==3) return max(tp->snd_cwnd*9/8, 2U);			// RTT Decrease
		else return max((tp->snd_cwnd * 922) / 1024, 2U);

		tp->qccqms.hy_low_window = tp->snd_ssthresh*3/4;
	} else
		return max((tp->snd_cwnd * beta) / BICTCP_BETA_SCALE, 2U);			// max(0.7*snd_cwnd，2)
}



static u32 mptcp_qcc_undo_cwnd(struct sock *sk)
{
	struct mptcp_qcc *qcc = inet_csk_ca(sk);
	return max(tcp_sk(sk)->snd_cwnd, qcc->last_max_cwnd);
}



static void mptcp_qcc_state(struct sock *sk, u8 new_state)
{
	if (new_state == TCP_CA_Loss) {
		mptcp_qcc_reset(inet_csk_ca(sk), sk);

		bictcp_hystart_reset(sk);
	}
}

static void hystart_update(struct sock *sk, u32 delay)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct mptcp_qcc *qcc = inet_csk_ca(sk);

	/* 启动hystart且exit point还没找到 */
	if (qcc->found & hystart_detect)
		return;

	if (after(tp->snd_una, qcc->end_seq))
		bictcp_hystart_reset(sk);

	if (hystart_detect & HYSTART_ACK_TRAIN) {
		u32 now = bictcp_clock();

		/* first detection parameter - ack-train detection */
		if ((s32)(now - qcc->last_ack) <= hystart_ack_delta) {
			qcc->last_ack = now;
			if ((s32)(now - qcc->qcc_roundStart) > qcc->delay_min >> 4) {
				qcc->found |= HYSTART_ACK_TRAIN;
				NET_INC_STATS(sock_net(sk),
					      LINUX_MIB_TCPHYSTARTTRAINDETECT);
				NET_ADD_STATS(sock_net(sk),
					      LINUX_MIB_TCPHYSTARTTRAINCWND,
					      tp->snd_cwnd);
				tp->snd_ssthresh = tp->snd_cwnd;
			}
		}
	}

	if (hystart_detect & HYSTART_DELAY) {
		/* obtain the minimum delay of more than sampling packets */
		if (qcc->curr_rtt > delay)
			qcc->curr_rtt = delay;

		// HYSTART delay obtain the minimum delay of more than sampling packets
		if (qcc->sample_cnt < HYSTART_MIN_SAMPLES) {
			if (qcc->curr_rtt == 0 || qcc->curr_rtt > delay)
				qcc->curr_rtt = delay;

			qcc->sample_cnt++;
		} else {
			if (qcc->curr_rtt > qcc->delay_min +
			    HYSTART_DELAY_THRESH(qcc->delay_min >> 3)) {
				qcc->found |= HYSTART_DELAY;
				NET_INC_STATS(sock_net(sk),
					      LINUX_MIB_TCPHYSTARTDELAYDETECT);
				NET_ADD_STATS(sock_net(sk),
					      LINUX_MIB_TCPHYSTARTDELAYCWND,
					      tp->snd_cwnd);
				tp->snd_ssthresh = tp->snd_cwnd;
			}
		}
	}
}


static void mptcp_qcc_pkts_acked(struct sock *sk, const struct ack_sample *sample)
{
	struct tcp_sock *tp = tcp_sk(sk);

	struct mptcp_qcc *qcc = inet_csk_ca(sk);
	u32 delay;

	/* Some calls are for duplicates without timetamps */
	if (sample->rtt_us < 0)
		return;

	/* Discard delay samples right after fast recovery */
	if (qcc->epoch_start && (s32)(tcp_jiffies32 - qcc->epoch_start) < HZ)
		return;

	delay = (sample->rtt_us << 3) / USEC_PER_MSEC;
	if (delay == 0)
		delay = 1;

	/* first time call or link delay decreases */
	if (qcc->delay_min == 0 || qcc->delay_min > delay)
		qcc->delay_min = delay;

	/* Never allow zero rtt or baseRTT */
	u32 vrtt = sample->rtt_us?sample->rtt_us:1;

	//ztg qcc 20230308
	//------------------------------------------
	tp->qccqms.RTT[7] = tp->qccqms.RTT[6];
	tp->qccqms.RTT[6] = tp->qccqms.RTT[5];
	tp->qccqms.RTT[5] = tp->qccqms.RTT[4];
	tp->qccqms.RTT[4] = tp->qccqms.RTT[3];
	tp->qccqms.RTT[3] = tp->qccqms.RTT[2];
	tp->qccqms.RTT[2] = tp->qccqms.RTT[1];
	tp->qccqms.RTT[1] = tp->qccqms.RTT[0];
	tp->qccqms.RTT[0] = vrtt;

	qcc->num_pkts_acked++;
	if (qcc->num_pkts_acked % 10 == 0) {
		u32 tao=300, eps=600;

		tp->qccqms.delta = tp->qccqms.id_1 = tp->qccqms.id_2 = tp->qccqms.id_3 = 0;
		for (u8 i=0; i<7; i++) {
			tp->qccqms.delta = tp->qccqms.RTT[i] - tp->qccqms.RTT[i+1];
			if ( ( -tao < tp->qccqms.delta ) && (tp->qccqms.delta < tao) ) tp->qccqms.id_1++;
			else if ( tp->qccqms.delta > eps ) tp->qccqms.id_2++;
			else if ( tp->qccqms.delta < -eps ) tp->qccqms.id_3++;
		}
		if ( tp->qccqms.nif == 2 ){						// WIFI
			if ( tp->qccqms.id_1 > 5 ) tp->qccqms.ID = 1;
			else if ( tp->qccqms.id_2 > 5 ) tp->qccqms.ID = 2;
			else if ( tp->qccqms.id_3 > 5 ) tp->qccqms.ID = 3;
		} else if( tp->qccqms.nif == 1 ){					// 4G
			if ( tp->qccqms.id_1 > 3 ) tp->qccqms.ID = 1;
			else if ( tp->qccqms.id_2 > 3 ) tp->qccqms.ID = 2;
			else if ( tp->qccqms.id_3 > 3 ) tp->qccqms.ID = 3;
		}
	}


	tp->qccqms.minRTT = min(tp->qccqms.minRTT, vrtt);
//	tp->qccqms.maxRTT = max(tp->qccqms.maxRTT, vrtt);
	tp->qccqms.cumRTT += vrtt;
	tp->qccqms.cntRTT++;

	delay = (tp->qccqms.minRTT << 3) / USEC_PER_MSEC;

	if (tp->qccqms.trigger != 1 && !tp->qccqms.tri_cond) tp->qccqms.trigger = 1;
	if (tp->qccqms.trigger != 1) tp->qccqms.tri_cond--;

	if (qcc->num_pkts_acked % 50 == 0) {
		mptcp_qcc_calculate(sk);
	}

	/* hystart triggers when cwnd is larger than some threshold */
	if (hystart && tcp_in_slow_start(tp) &&
	    tp->snd_cwnd >= tp->qccqms.hy_low_window)
		hystart_update(sk, delay);
}



static struct tcp_congestion_ops mptcpqcc __read_mostly = {
	.owner		= THIS_MODULE,
	.name		= "qcc",
	.init		= mptcp_qcc_init,

	.ssthresh	= mptcp_qcc_ssthresh,

	.qcc_cong_avoid = mptcp_qcc_cong_avoid,

//	.set_state	= bictcp_state,
	.set_state	= mptcp_qcc_state,

//	.undo_cwnd	= tcp_reno_undo_cwnd,
	.undo_cwnd	= mptcp_qcc_undo_cwnd,

	.cwnd_event	= bictcp_cwnd_event,

//	.pkts_acked     = bictcp_acked,
	.pkts_acked	= mptcp_qcc_pkts_acked,
};

static int __init mptcp_qcc_register(void)
{
	BUILD_BUG_ON(sizeof(struct mptcp_qcc) > ICSK_CA_PRIV_SIZE);

	/* Precompute a bunch of the scaling factors that are used per-packet
	 * based on SRTT of 100ms
	 */

	beta_scale = 8*(BICTCP_BETA_SCALE+beta) / 3
		/ (BICTCP_BETA_SCALE - beta);

	cube_rtt_scale = (bic_scale * 10);	/* 1024*c/rtt */

	/* calculate the "K" for (wmax-cwnd) = c/rtt * K^3
	 *  so K = cubic_root( (wmax-cwnd)*rtt/c )
	 * the unit of K is bictcp_HZ=2^10, not HZ
	 *
	 *  c = bic_scale >> 10
	 *  rtt = 100ms
	 *
	 * the following code has been designed and tested for
	 * cwnd < 1 million packets
	 * RTT < 100 seconds
	 * HZ < 1,000,00  (corresponding to 10 nano-second)
	 */

	/* 1/c * 2^2*bictcp_HZ * srtt */
	cube_factor = 1ull << (10+3*BICTCP_HZ); /* 2^40 */

	/* divide by bic_scale and by constant Srtt (100ms) */
	do_div(cube_factor, bic_scale * 10);

	return tcp_register_congestion_control(&mptcpqcc);
}

static void __exit mptcp_qcc_unregister(void)
{
	tcp_unregister_congestion_control(&mptcpqcc);
}

module_init(mptcp_qcc_register);
module_exit(mptcp_qcc_unregister);

MODULE_AUTHOR("Tongguang Zhang");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("MPTCP QoE-Driven Congestion Controller (QCC)");		// MODULE_DESCRIPTION("MPTCP QCC");
MODULE_VERSION("0.1");
