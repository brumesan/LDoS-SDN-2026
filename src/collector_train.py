#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Pure collection mode

- Door State Detection (Algorithm 1)
- CSV showing consistency with Eqs. (1)–(9)

"""

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub
import csv, time, statistics, math, os
from collections import deque, defaultdict
import numpy as np
import pandas as pd


def entropy_from_counts(counts):
    total = sum(counts)
    if total <= 0:
        return 0.0
    ent = 0.0
    for c in counts:
        if c > 0:
            p = c / total
            # base 2 as in the paper (Eqs. 5 and 8)
            ent -= p * math.log(p, 2)
    return ent


class Collector(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Collector, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.interval = 0.5

        # Port stats: (rx_bytes, tx_bytes, rx_pkts, tx_pkts, ts)
        self.port_stats = {}

        self.buffer = defaultdict(dict)     # dpid -> port -> (in_Bps, out_Bps, in_pps, out_pps)
        self.prev_flow_stats = {}           # dpid -> prev totals for deltas

        # === CSV ===
        results_dir = "/home/$USER/mininet/mininet/results"
        os.makedirs(results_dir, exist_ok=True)
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        self.csv_file = os.path.join(results_dir, f"collection_output_{timestamp}.csv")

        # === Parameters ===
        self.WINDOW_SIZE = 30
        self.k = 3
        self.th = 0.0026
        self.sigma_floor = 1e-6

        # Bottleneck link bandwidth B (bytes/s). Ex.: 45 Mbps -> 5_625_000 B/s
        self.B = 45_000_000 / 8

        # Time series (global rates by DPID)
        self.series_bytesudp = defaultdict(lambda: deque(maxlen=self.WINDOW_SIZE))
        self.series_packetsudp = defaultdict(lambda: deque(maxlen=self.WINDOW_SIZE))
        self.series_bytestcp = defaultdict(lambda: deque(maxlen=self.WINDOW_SIZE))
        self.series_packetstcp = defaultdict(lambda: deque(maxlen=self.WINDOW_SIZE))

        # PNF/PPNF series by port
        self.series_pnf = defaultdict(lambda: defaultdict(lambda: deque(maxlen=self.WINDOW_SIZE)))
        self.series_ppnf = defaultdict(lambda: defaultdict(lambda: deque(maxlen=self.WINDOW_SIZE)))

        # CSV header
        with open(self.csv_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                "timestamp","switch","port",
                "vin_Bps","vout_Bps","pnf","ppnf",
                "mean_udp","cv_udp","mean_pkt_udp","entropy_udp",
                "mean_tcp","cv_tcp","ratio_tcp","entropy_tcp",
                "mean_pnf","mean_ppnf",
                "port_state","port_outlier_prop"
            ])

        self.logger.info("Collector started in PURE COLLECTION mode (no prediction/mitigation).")
        self.monitor_thread = hub.spawn(self._monitor)

    # ============= Installs TCP/UDP base flows + ARP + anti-Packet-In silencing. ===========
    
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        self.datapaths[dp.id] = dp
        parser = dp.ofproto_parser
        ofp = dp.ofproto
        actions = [parser.OFPActionOutput(ofp.OFPP_NORMAL)]

        # 1. Proactive rules for TCP and UDP
        for proto in [6, 17]:
            match = parser.OFPMatch(eth_type=0x0800, ip_proto=proto)
            dp.send_msg(parser.OFPFlowMod(
                datapath=dp,
                priority=40000,
                match=match,
                instructions=[parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
            ))

        # 2. Rule for ARP
        match_arp = parser.OFPMatch(eth_type=0x0806)
        dp.send_msg(parser.OFPFlowMod(
            datapath=dp,
            priority=1000,
            match=match_arp,
            instructions=[parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        ))

        # 3. Silence rule (anti-Packet-In)
        match_all = parser.OFPMatch()
        dp.send_msg(parser.OFPFlowMod(
            datapath=dp,
            priority=10,
            match=match_all,
            instructions=[]
        ))

    # ======= Main monitoring loop ==========    
    def _monitor(self):
        while True:
            for dp in list(self.datapaths.values()):
                parser = dp.ofproto_parser
                try:
                    dp.send_msg(parser.OFPPortStatsRequest(dp, 0, dp.ofproto.OFPP_ANY))
                    dp.send_msg(parser.OFPFlowStatsRequest(
                        dp, 0, dp.ofproto.OFPTT_ALL, dp.ofproto.OFPP_ANY, dp.ofproto.OFPG_ANY, 0, 0,
                        parser.OFPMatch(eth_type=0x0800)
                    ))
                except Exception as e:
                    self.logger.debug("Error sending stats to dp %s: %s", getattr(dp, 'id', None), e)
            hub.sleep(self.interval)

    # ===== Port statistics collection =========
    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        dpid = ev.msg.datapath.id
        now = time.time()
        for stat in ev.msg.body:
            port = stat.port_no
            if port <= 0 or port >= 0xff00:
                continue

            # CORRECT: rx = v_in, tx = v_out
            rxB, txB = stat.rx_bytes, stat.tx_bytes
            rxP, txP = stat.rx_packets, stat.tx_packets

            key = (dpid, port)
            if key not in self.port_stats:
                self.port_stats[key] = (rxB, txB, rxP, txP, now)
                continue

            last_rxB, last_txB, last_rxP, last_txP, last_ts = self.port_stats[key]
            dt = now - last_ts
            if dt <= 0:
                continue

            in_Bps  = max(0.0, (rxB - last_rxB) / dt)
            out_Bps = max(0.0, (txB - last_txB) / dt)
            in_pps  = max(0.0, (rxP - last_rxP) / dt)
            out_pps = max(0.0, (txP - last_txP) / dt)

            self.port_stats[key] = (rxB, txB, rxP, txP, now)
            self.buffer[dpid][port] = (in_Bps, out_Bps, in_pps, out_pps)

            # Eq. (1) and Eq. (9)
            pnf  = in_Bps / out_Bps if out_Bps > 0 else 0.0
            ppnf = in_pps / out_pps if out_pps > 0 else 0.0

            self.series_pnf[dpid][port].append(pnf)
            self.series_ppnf[dpid][port].append(ppnf)

            self._analyze_port(dpid, port, in_Bps, out_Bps, pnf, ppnf)

    # ===== Flow statistics collection ============    
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        dpid = ev.msg.datapath.id
        now = time.time()
        udp_b = udp_p = tcp_b = tcp_p = 0

        for stat in ev.msg.body:
            m = stat.match
            proto = None
            try:
                proto = m.get("ip_proto") if hasattr(m, 'get') else getattr(m, 'ip_proto', None)
            except Exception:
                proto = None
            if proto == 17:
                udp_b += stat.byte_count
                udp_p += stat.packet_count
            elif proto == 6:
                tcp_b += stat.byte_count
                tcp_p += stat.packet_count

        prev = self.prev_flow_stats.get(dpid)
        if prev is None:
            self.prev_flow_stats[dpid] = {"t": now, "ub": udp_b, "up": udp_p, "tb": tcp_b, "tp": tcp_p}
            return

        dt = now - prev["t"]
        if dt <= 0:
            return

        # rates (delta/dt) – in B/s and pps
        self.series_bytesudp[dpid].append(max(0.0, (udp_b - prev["ub"]) / dt))
        self.series_packetsudp[dpid].append(max(0.0, (udp_p - prev["up"]) / dt))
        self.series_bytestcp[dpid].append(max(0.0, (tcp_b - prev["tb"]) / dt))
        self.series_packetstcp[dpid].append(max(0.0, (tcp_p - prev["tp"]) / dt))

        self.prev_flow_stats[dpid] = {"t": now, "ub": udp_b, "up": udp_p, "tb": tcp_b, "tp": tcp_p}

    # ====== Analysis and recording ==========
    def _analyze_port(self, dpid, port, in_Bps, out_Bps, pnf, ppnf):
        now_ts = time.strftime("%Y-%m-%d %H:%M:%S")

        # Series to features 
        b_udp, p_udp = list(self.series_bytesudp[dpid]), list(self.series_packetsudp[dpid])
        b_tcp, p_tcp = list(self.series_bytestcp[dpid]), list(self.series_packetstcp[dpid])

        # === FEATURES ===
        # ub_ave (Eq. 2) → mean_udp (normalized by B)
        mean_udp = (statistics.mean(b_udp) / self.B) if b_udp else 0.0
        # ub_cov (Eq. 3) → cv_udp
        cv_udp = (statistics.pstdev(b_udp) / statistics.mean(b_udp)) if len(b_udp) > 1 and statistics.mean(b_udp) > 0 else 0.0
        # upl_ave (Eq. 4) → mean_pkt_udp
        sum_bu, sum_pu = sum(b_udp), sum(p_udp)
        mean_pkt_udp = (sum_bu / sum_pu) if sum_pu > 0 else 0.0
        # up_ent (Eq. 5) → entropy_udp
        entropy_udp = entropy_from_counts(p_udp) if p_udp else 0.0

        # tb_ave (Eq. 7) → mean_tcp
        mean_tcp = (statistics.mean(b_tcp) / self.B) if b_tcp else 0.0
        # tb_cov (Eq. 6) → cv_tcp
        cv_tcp = (statistics.pstdev(b_tcp) / statistics.mean(b_tcp)) if len(b_tcp) > 1 and statistics.mean(b_tcp) > 0 else 0.0
        # extra: keeps ratio_tcp for compatibility
        ratio_tcp = (statistics.mean(b_tcp) / (statistics.mean(b_tcp) + statistics.mean(b_udp))) if b_tcp and b_udp and (statistics.mean(b_tcp)+statistics.mean(b_udp))>0 else (1.0 if b_tcp and not b_udp else 0.0)
        # tp_ent (Eq. 8) → entropy_tcp
        entropy_tcp = entropy_from_counts(p_tcp) if p_tcp else 0.0

        # PNF / PPNF medium-sized
        mean_pnf = statistics.mean(self.series_pnf[dpid][port]) if self.series_pnf[dpid][port] else 0.0
        mean_ppnf = statistics.mean(self.series_ppnf[dpid][port]) if self.series_ppnf[dpid][port] else 0.0

        # Port State Detection (Alg. 1)
        pnf_series = list(self.series_pnf[dpid][port])
        port_outlier_prop = 0.0
        port_state = "normal"
        if len(pnf_series) >= 5:
            mu = float(np.mean(pnf_series))
            sigma = float(np.std(pnf_series, ddof=0))
            sigma = max(sigma, self.sigma_floor)
            diffs = np.abs(np.array(pnf_series) - mu)
            port_outlier_prop = float(np.mean(diffs > (self.k * sigma)))
            port_state = "abnormal" if port_outlier_prop > self.th else "normal"

        # Save as CSV 
        with open(self.csv_file, "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                now_ts, dpid, port,
                f"{in_Bps:.2f}", f"{out_Bps:.2f}", f"{pnf:.6f}", f"{ppnf:.6f}",
                f"{mean_udp:.6f}", f"{cv_udp:.6f}", f"{mean_pkt_udp:.6f}", f"{entropy_udp:.6f}",
                f"{mean_tcp:.6f}", f"{cv_tcp:.6f}", f"{ratio_tcp:.6f}", f"{entropy_tcp:.6f}",
                f"{mean_pnf:.6f}", f"{mean_ppnf:.6f}",
                port_state, f"{port_outlier_prop:.6f}"
            ])

        self.logger.info(f"[Switch {dpid}] Port {port} | port_state={port_state} | pnf={pnf:.4f} | ppnf={ppnf:.4f}")

# EOF
