#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Ryu + XGBoost 

- Implements Algorithm 1 (Port State Detection: mu +/- k*sigma + threshold th)
- Only executes XGBoost (Traffic State Detection) when the port is considered "abnormal"
- Maintains output CSV with columns: timestamp, switch, port, features, port_state, status, predict, prob
- Applies mitigation (FlowMod DROP) only when both phases indicate an attack
- Adjustable parameters: WINDOW_SIZE, k, th, sigma_floor, PROB_THRESHOLD

"""

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub
import csv, time, statistics, math, os
from collections import deque, defaultdict
import joblib
import xgboost as xgb
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
            ent -= p * math.log(p)
    return ent


class TridentCollector(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(TridentCollector, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.interval = 0.5
        self.port_stats = {}
        self.buffer = defaultdict(dict)
        self.prev_flow_stats = {}
        self.blacklist = set()

        # === Modelo XGBoost + Scaler ===
        self.model_path = "trident_xgb_model.json"
        self.scaler_path = "trident_scaler.pkl"
        if os.path.exists(self.model_path) and os.path.exists(self.scaler_path):
            try:
                self.model = xgb.XGBClassifier()
                self.model.load_model(self.model_path)
                self.scaler = joblib.load(self.scaler_path)
                self.logger.info("XGBoost and Scaler models loaded successfully.")
            except Exception as e:
                self.logger.exception("Failed to load model/scaler: %s", e)
                self.model = None
                self.scaler = None
        else:
            self.model = None
            self.scaler = None
            self.logger.warning("Model/Scaler not found — prediction disabled. ")

        # === CSV Path ===
        output_dir = "results"
        os.makedirs(output_dir, exist_ok=True)
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        self.csv_file = os.path.join(output_dir, f"trident_output_{timestamp}.csv")

        # === Algorithm parameters ===
        self.WINDOW_SIZE = 30
        self.k = 3
        self.th = 0.0026
        self.sigma_floor = 1e-6
        self.PROB_THRESHOLD = 0.5

        # Time series
        self.series_bytesudp = defaultdict(lambda: deque(maxlen=self.WINDOW_SIZE))
        self.series_packetsudp = defaultdict(lambda: deque(maxlen=self.WINDOW_SIZE))
        self.series_bytestcp = defaultdict(lambda: deque(maxlen=self.WINDOW_SIZE))
        self.series_packetstcp = defaultdict(lambda: deque(maxlen=self.WINDOW_SIZE))
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
                "port_state","port_outlier_prop",
                "status","alert_msg","predict","prob"
            ])

        self.monitor_thread = hub.spawn(self._monitor)

    # ========== TCP/UDP streams ==========
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        self.datapaths[dp.id] = dp
        self._install_proto_flows(dp)

    def _install_proto_flows(self, dp):
        parser = dp.ofproto_parser
        ofp = dp.ofproto
        actions = [parser.OFPActionOutput(ofp.OFPP_NORMAL)]
        for proto in [6, 17]:
            match = parser.OFPMatch(eth_type=0x0800, ip_proto=proto)
            dp.send_msg(parser.OFPFlowMod(datapath=dp, priority=40000, match=match,
                                          instructions=[parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]))

    # ========== Collect ==========
    def _monitor(self):
        while True:
            for dp in list(self.datapaths.values()):
                parser = dp.ofproto_parser
                try:
                    dp.send_msg(parser.OFPPortStatsRequest(dp, 0, dp.ofproto.OFPP_ANY))
                    dp.send_msg(parser.OFPFlowStatsRequest(dp, 0, dp.ofproto.OFPTT_ALL,
                                                           dp.ofproto.OFPP_ANY, dp.ofproto.OFPG_ANY, 0, 0,
                                                           parser.OFPMatch(eth_type=0x0800)))
                except Exception as e:
                    self.logger.debug("Error requesting stats for dp %s: %s", getattr(dp, 'id', None), e)
            hub.sleep(self.interval)

    # ===== Port Stats =======
    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        dpid = ev.msg.datapath.id
        now = time.time()
        for stat in ev.msg.body:
            port = stat.port_no
            if port <= 0 or port >= 0xff00:
                continue
            vin, vout = stat.tx_bytes, stat.rx_bytes
            key = (dpid, port)
            if key not in self.port_stats:
                self.port_stats[key] = (vin, vout, now)
                continue
            last_vin, last_vout, last_ts = self.port_stats[key]
            dt = now - last_ts
            if dt <= 0:
                continue
            rate_in = max(0.0, (vin - last_vin) / dt)
            rate_out = max(0.0, (vout - last_vout) / dt)
            self.port_stats[key] = (vin, vout, now)
            self.buffer[dpid][port] = (rate_in, rate_out)
            pnf = rate_in / rate_out if rate_out > 0 else 0.0
            paired = port + 1 if port % 2 == 1 else port - 1
            ppnf = 0.0
            if paired in self.buffer[dpid] and self.buffer[dpid][paired][1] > 0:
                vin_p, vout_p = self.buffer[dpid][paired]
                ppnf = vin_p / vout_p if vout_p > 0 else 0.0
            self.series_pnf[dpid][port].append(pnf)
            self.series_ppnf[dpid][port].append(ppnf)
            self._detect_and_record(dpid, port, rate_in, rate_out, pnf, ppnf)

    # ==== Flow Stats =====
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        dpid = ev.msg.datapath.id
        now = time.time()
        udp_b = udp_p = tcp_b = tcp_p = 0
        for stat in ev.msg.body:
            proto = None
            try:
                proto = stat.match.get("ip_proto") if hasattr(stat.match, 'get') else getattr(stat.match, 'ip_proto', None)
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
        self.series_bytesudp[dpid].append(max(0, (udp_b - prev["ub"]) / dt))
        self.series_packetsudp[dpid].append(max(0, (udp_p - prev["up"]) / dt))
        self.series_bytestcp[dpid].append(max(0, (tcp_b - prev["tb"]) / dt))
        self.series_packetstcp[dpid].append(max(0, (tcp_p - prev["tp"]) / dt))
        self.prev_flow_stats[dpid] = {"t": now, "ub": udp_b, "up": udp_p, "tb": tcp_b, "tp": tcp_p}

    # ===== Detection + Mitigation =====
    def _detect_and_record(self, dpid, port, rate_in, rate_out, pnf, ppnf):
        now_ts = time.strftime("%Y-%m-%d %H:%M:%S")

        # ===== Feature calculation ====
        b_udp, p_udp = list(self.series_bytesudp[dpid]), list(self.series_packetsudp[dpid])
        b_tcp, p_tcp = list(self.series_bytestcp[dpid]), list(self.series_packetstcp[dpid])

        mean_udp = statistics.mean(b_udp) if b_udp else 0.0
        cv_udp = statistics.pstdev(b_udp) / mean_udp if len(b_udp) > 1 and mean_udp > 0 else 0.0
        mean_pkt_udp = statistics.mean(p_udp) if p_udp else 0.0
        entropy_udp = entropy_from_counts(p_udp) if p_udp else 0.0

        mean_tcp = statistics.mean(b_tcp) if b_tcp else 0.0
        cv_tcp = statistics.pstdev(b_tcp) / mean_tcp if len(b_tcp) > 1 and mean_tcp > 0 else 0.0
        ratio_tcp = mean_tcp / (mean_tcp + mean_udp) if (mean_tcp + mean_udp) > 0 else 0.0
        entropy_tcp = entropy_from_counts(p_tcp) if p_tcp else 0.0

        mean_pnf = statistics.mean(self.series_pnf[dpid][port]) if self.series_pnf[dpid][port] else 0.0
        mean_ppnf = statistics.mean(self.series_ppnf[dpid][port]) if self.series_ppnf[dpid][port] else 0.0

        # ==== Port State Detection ====
        pnf_series = list(self.series_pnf[dpid][port])
        port_outlier_prop = 0.0
        port_state = "unknown"
        if len(pnf_series) >= 5:
            mu = float(np.mean(pnf_series))
            sigma = float(np.std(pnf_series, ddof=0))
            sigma = max(sigma, self.sigma_floor)
            diffs = np.abs(np.array(pnf_series) - mu)
            port_outlier_prop = float(np.mean(diffs > (self.k * sigma)))
            port_state = "abnormal" if port_outlier_prop > self.th else "normal"
        else:
            port_state = "normal"

        # === XGBoost only runs if port_state == 'abnormal' ===
        predict, prob = "-", "-"
        status, alert_msg = "NORM", "OK"
        if port_state == "abnormal" and self.model is not None and self.scaler is not None:
            feature_names = [
                "mean_udp","cv_udp","mean_pkt_udp","entropy_udp",
                "mean_tcp","cv_tcp","ratio_tcp","entropy_tcp",
                "mean_pnf","mean_ppnf"
            ]
            X_df = pd.DataFrame([[mean_udp, cv_udp, mean_pkt_udp, entropy_udp,
                                  mean_tcp, cv_tcp, ratio_tcp, entropy_tcp,
                                  mean_pnf, mean_ppnf]], columns=feature_names)
            try:
                X_scaled = self.scaler.transform(X_df.values)

                # Get attack probability (class 1)
                y_prob = self.model.predict_proba(X_scaled)[0, 1]

                predict = 1 if y_prob > self.PROB_THRESHOLD else 0
                prob = round(float(y_prob), 6)

                if predict == 1 and prob > self.PROB_THRESHOLD:
                    status = "ALERT_XGB"
                    alert_msg = f"Attack detected (prob={prob:.3f})"
                    src_ip, dst_ip, proto = "0.0.0.0", "0.0.0.0", 17
                    self._apply_mitigation(dpid, src_ip, dst_ip, proto)
                else:
                    status = "NORM"
                    alert_msg = "XGB_no_attack"

            except Exception as e:
                self.logger.exception("Error during XGBoost predication: %s", e)
                status = "NORM"
                alert_msg = "XGB_error"
        else:
            if port_state == "abnormal":
                status = "ALERT_PORT"
                alert_msg = f"Port anomaly (prop={port_outlier_prop:.6f})"
            else:
                status = "NORM"
                alert_msg = "OK"

        # === CSV recording ====
        with open(self.csv_file, "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                now_ts, dpid, port,
                f"{rate_in:.2f}", f"{rate_out:.2f}", f"{pnf:.6f}", f"{ppnf:.6f}",
                f"{mean_udp:.6f}", f"{cv_udp:.6f}", f"{mean_pkt_udp:.6f}", f"{entropy_udp:.6f}",
                f"{mean_tcp:.6f}", f"{cv_tcp:.6f}", f"{ratio_tcp:.6f}", f"{entropy_tcp:.6f}",
                f"{mean_pnf:.6f}", f"{mean_ppnf:.6f}",
                port_state, f"{port_outlier_prop:.6f}",
                status, alert_msg, predict, prob
            ])

        self.logger.info(f"[Switch {dpid}] Port {port} | port_state={port_state} | status={status} | prob={prob}")

    # === Mitigation ===
    def _apply_mitigation(self, dpid, src_ip, dst_ip, proto):
        dp = self.datapaths.get(dpid)
        if not dp:
            self.logger.warning("Datapath %s not found for mitigation.", dpid)
            return
        parser = dp.ofproto_parser
        ofp = dp.ofproto

        match = parser.OFPMatch(
            eth_type=0x0800,
            ipv4_src=src_ip,
            ipv4_dst=dst_ip,
            ip_proto=proto
        )

        drop = parser.OFPFlowMod(
            datapath=dp,
            table_id=0,
            cookie=0xDEADBEEF,
            priority=65535,
            match=match,
            instructions=[],
            hard_timeout=60,
            idle_timeout=30
        )
        try:
            dp.send_msg(drop)
            self.logger.warning(f"[MITIGATION] Switch {dpid} — DROP flow applied (src={src_ip}, dst={dst_ip}, proto={proto})")
        except Exception as e:
            self.logger.exception("Failed to send FlowMod drop: %s", e)


# EOF
