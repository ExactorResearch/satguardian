#!/usr/bin/env python3
"""
===============================================================================
 GUARDIAN-TOP: Real-Time Interactive Monitor for Guardian WAF
 Inspired by htop/btop — Metrics, Sub-Millisecond Latency, and Forensic Ledger
===============================================================================
"""

import os
import sys
import time
import curses
import sqlite3
import argparse
from datetime import datetime

# Reduce ESC key delay for instantaneous response in ncurses
os.environ.setdefault("ESCDELAY", "25")

DEFAULT_DB_PATHS = [
    "/var/lib/satguardian/waf_ledger.db",
    "/etc/satguardian/waf_ledger.db",
    "/var/lib/satguardian/waf_ledger.db",
    "/etc/satguardian/waf_ledger.db",
    "waf_ledger.db",
    "../waf_ledger.db",
]

def find_database(cli_path=None):
    if cli_path and os.path.exists(cli_path):
        return cli_path
    for path in DEFAULT_DB_PATHS:
        if os.path.exists(path):
            return path
    return None

def get_db_connection(db_path):
    try:
        uri = f"file:{os.path.abspath(db_path)}?mode=ro"
        conn = sqlite3.connect(uri, uri=True, timeout=2.0)
        conn.row_factory = sqlite3.Row
        return conn
    except Exception:
        return None

def safe_addstr(stdscr, y, x, text, attr=0):
    """
    Safely writes text in curses without exceeding screen boundaries
    or writing to bottom-right corner (max_y - 1, max_x - 1) which throws ERR.
    """
    try:
        max_y, max_x = stdscr.getmaxyx()
        if y < 0 or y >= max_y or x < 0 or x >= max_x:
            return
        avail = max_x - x
        if y == max_y - 1:
            avail -= 1  # Avoids automatic overflow on the last cell in curses
        if avail <= 0:
            return
        stdscr.addstr(y, x, str(text)[:avail], attr)
    except curses.error:
        pass

def draw_gauge(stdscr, y, x, label, pct, width, color_pair):
    if width <= 0:
        return
    label_text = f"{label:12s} ["
    safe_addstr(stdscr, y, x, label_text, curses.color_pair(1) | curses.A_BOLD)
    bar_width = max(6, width - len(label_text) - 8)
    filled = int(round(bar_width * (pct / 100.0)))
    filled = min(bar_width, max(0, filled))

    bar_x = x + len(label_text)
    safe_addstr(stdscr, y, bar_x, "|" * filled, color_pair | curses.A_BOLD)
    safe_addstr(stdscr, y, bar_x + filled, " " * (bar_width - filled), curses.color_pair(1))
    safe_addstr(stdscr, y, bar_x + bar_width, f"] {pct:5.1f}%", curses.color_pair(1))

class SatguardianTop:
    def __init__(self, db_path, refresh_rate=1.0):
        self.db_path = db_path
        self.refresh_rate = refresh_rate
        self.filter_mode = "ALL"  # "ALL" or "BLOCK"
        self.paused = False
        self.selected_idx = 0
        self.scroll_offset = 0
        self.modal_scroll_offset = 0
        self.records_cache = []
        self.show_detail = False

    def fetch_stats(self, conn):
        stats = {
            "total": 0,
            "blocked": 0,
            "allowed": 0,
            "block_rate": 0.0,
            "avg_latency": 0.0,
            "p95_latency": 0.0,
            "max_latency": 0.0,
            "pending_anomalies": 0,
            "categories": {},
            "recent_simplification": None,
        }
        if not conn:
            return stats

        try:
            cur = conn.cursor()
            cur.execute("""
                SELECT 
                    count(*) as total,
                    sum(case when UPPER(action) = 'BLOCK' then 1 else 0 end) as blocked,
                    sum(case when UPPER(action) = 'ALLOW' then 1 else 0 end) as allowed,
                    avg(latency_us) as avg_latency,
                    max(latency_us) as max_latency
                FROM audit_log
            """)
            row = cur.fetchone()
            if row and row["total"]:
                stats["total"] = row["total"] or 0
                stats["blocked"] = row["blocked"] or 0
                stats["allowed"] = row["allowed"] or 0
                stats["avg_latency"] = row["avg_latency"] or 0.0
                stats["max_latency"] = row["max_latency"] or 0.0
                if stats["total"] > 0:
                    stats["block_rate"] = (stats["blocked"] / stats["total"]) * 100.0

            # P95 estimation
            cur.execute("""
                SELECT latency_us FROM audit_log 
                ORDER BY latency_us ASC 
                LIMIT 1 OFFSET CAST((SELECT count(*) FROM audit_log) * 0.95 AS INTEGER)
            """)
            p95_row = cur.fetchone()
            if p95_row and p95_row[0] is not None:
                stats["p95_latency"] = p95_row[0]

            # Category distribution
            cur.execute("""
                SELECT category, count(*) as cnt 
                FROM audit_log 
                WHERE UPPER(action) = 'BLOCK'
                GROUP BY category 
                ORDER BY cnt DESC 
                LIMIT 5
            """)
            for r in cur.fetchall():
                cat = r["category"] or "unknown"
                stats["categories"][cat] = r["cnt"]

            # Pending anomalies
            try:
                cur.execute("SELECT count(*) FROM novel_anomalies WHERE status = 'PENDING'")
                r_anom = cur.fetchone()
                if r_anom:
                    stats["pending_anomalies"] = r_anom[0]
            except Exception:
                pass

            # Last cloud simplification
            try:
                cur.execute("""
                    SELECT reduction_percent, original_gates, new_gates, timestamp 
                    FROM cloud_simplification_history 
                    ORDER BY id DESC LIMIT 1
                """)
                r_simp = cur.fetchone()
                if r_simp:
                    stats["recent_simplification"] = {
                        "reduction": r_simp["reduction_percent"],
                        "original": r_simp["original_gates"],
                        "new": r_simp["new_gates"],
                        "time": r_simp["timestamp"],
                    }
            except Exception:
                pass

        except Exception:
            pass

        return stats

    def fetch_recent_logs(self, conn, limit=250):
        if not conn:
            return []
        try:
            cur = conn.cursor()
            query = """
                SELECT id, request_id, timestamp, client_ip, method, path, action, category, latency_us, matched_rules, causal_proof
                FROM audit_log
            """
            if self.filter_mode == "BLOCK":
                query += " WHERE UPPER(action) = 'BLOCK'"
            query += f" ORDER BY id DESC LIMIT {limit}"
            cur.execute(query)
            return cur.fetchall()
        except Exception:
            return []

    def run(self, stdscr):
        try:
            curses.curs_set(0)
        except Exception:
            pass

        # Enable special keys and mouse capture
        stdscr.keypad(True)
        stdscr.nodelay(True)
        stdscr.timeout(int(self.refresh_rate * 1000))

        try:
            curses.mousemask(curses.ALL_MOUSE_EVENTS | curses.REPORT_MOUSE_POSITION)
        except Exception:
            pass

        # Color palette optimized for htop style
        curses.start_color()
        try:
            curses.use_default_colors()
        except Exception:
            pass
        curses.init_pair(1, curses.COLOR_WHITE, -1)
        curses.init_pair(2, curses.COLOR_GREEN, -1)
        curses.init_pair(3, curses.COLOR_RED, -1)
        curses.init_pair(4, curses.COLOR_CYAN, -1)
        curses.init_pair(5, curses.COLOR_YELLOW, -1)
        curses.init_pair(6, curses.COLOR_MAGENTA, -1)
        curses.init_pair(7, curses.COLOR_BLACK, curses.COLOR_CYAN)
        curses.init_pair(8, curses.COLOR_WHITE, curses.COLOR_RED)
        curses.init_pair(9, curses.COLOR_BLACK, curses.COLOR_GREEN)
        curses.init_pair(10, curses.COLOR_WHITE, curses.COLOR_BLUE)

        last_tick = 0
        stats = {}
        logs = []

        while True:
            now = time.time()
            if not self.paused and (now - last_tick >= self.refresh_rate or last_tick == 0):
                conn = get_db_connection(self.db_path)
                stats = self.fetch_stats(conn)
                logs = self.fetch_recent_logs(conn, limit=250)
                self.records_cache = logs
                if conn:
                    conn.close()
                last_tick = now

            max_y, max_x = stdscr.getmaxyx()
            stdscr.erase()

            # Small terminal protection
            if max_y < 10 or max_x < 50:
                safe_addstr(stdscr, 0, 0, "Window too small. Please resize terminal.", curses.color_pair(3) | curses.A_BOLD)
                try:
                    stdscr.refresh()
                except curses.error:
                    pass
                time.sleep(0.3)
                continue

            # --- TOP HEADER ---
            title = " GUARDIAN-TOP :: HIGH-PERFORMANCE WAF MONITOR & FORMAL PROOF AUDITOR "
            safe_addstr(stdscr, 0, 0, title, curses.color_pair(7) | curses.A_BOLD)
            status_line = f" [DB: {os.path.basename(self.db_path)}] [Filter: {self.filter_mode}] [Rate: {self.refresh_rate:.1f}s] {'[PAUSED]' if self.paused else '[LIVE]'}"
            if len(title) + len(status_line) < max_x:
                safe_addstr(stdscr, 0, max_x - len(status_line), status_line, curses.color_pair(7))

            # --- METRICS & GAUGES SECTION (Lines 2 to 8) ---
            col_mid = max(30, max_x // 2)

            # Left Column: Throughput and Performance
            allowed_pct = (stats.get("allowed", 0) / stats["total"] * 100.0) if stats.get("total", 0) > 0 else 0.0
            block_pct = stats.get("block_rate", 0.0)

            gauge_w = max(15, col_mid - 4)
            draw_gauge(stdscr, 2, 2, "ALLOW TRAFFIC", allowed_pct, gauge_w, curses.color_pair(2))
            draw_gauge(stdscr, 3, 2, "BLOCK ATTACKS", block_pct, gauge_w, curses.color_pair(3))

            lat_avg_str = f"Avg: {stats.get('avg_latency', 0.0):6.1f}µs"
            lat_p95_str = f"P95: {stats.get('p95_latency', 0.0):6.1f}µs"
            lat_max_str = f"Max: {stats.get('max_latency', 0.0):6.1f}µs"
            safe_addstr(stdscr, 5, 2, f"Latency: {lat_avg_str}  {lat_p95_str}  {lat_max_str}", curses.color_pair(4) | curses.A_BOLD)

            # Right Column: Counters, Threat Categories and Cloud
            if col_mid < max_x - 10:
                safe_addstr(stdscr, 2, col_mid, f"Total: {stats.get('total', 0):,} | Block: {stats.get('blocked', 0):,} | Allow: {stats.get('allowed', 0):,}", curses.color_pair(1) | curses.A_BOLD)

                cat_items = [f"{k.upper()}:{v}" for k, v in stats.get("categories", {}).items()]
                cat_str = "Attacks: " + (" | ".join(cat_items) if cat_items else "None detected")
                safe_addstr(stdscr, 3, col_mid, cat_str, curses.color_pair(6) | curses.A_BOLD)

                anom_str = f"Novel Anomalies: {stats.get('pending_anomalies', 0)} PENDING"
                safe_addstr(stdscr, 4, col_mid, anom_str, curses.color_pair(5))

                if stats.get("recent_simplification"):
                    simp = stats["recent_simplification"]
                    simp_str = f"Cloud Synth: {simp['reduction']:.1f}% reduction ({simp['original']}->{simp['new']})"
                    safe_addstr(stdscr, 5, col_mid, simp_str, curses.color_pair(4))

            # Horizontal separator
            safe_addstr(stdscr, 7, 0, "─" * (max_x - 1), curses.color_pair(1))

            # --- TABLE HEADER (Line 8) with Scroll position indicator ---
            row_y = 9
            table_height = max(1, max_y - row_y - 2)
            total_records = len(self.records_cache)

            # Dynamic Viewport Calculations (Scroll)
            if total_records > 0:
                self.selected_idx = max(0, min(self.selected_idx, total_records - 1))
                if self.selected_idx < self.scroll_offset:
                    self.scroll_offset = self.selected_idx
                elif self.selected_idx >= self.scroll_offset + table_height:
                    self.scroll_offset = self.selected_idx - table_height + 1
                max_offset = max(0, total_records - table_height)
                self.scroll_offset = max(0, min(self.scroll_offset, max_offset))
                pos_str = f" [{self.selected_idx + 1}/{total_records}] "
            else:
                self.selected_idx = 0
                self.scroll_offset = 0
                pos_str = " [0/0] "

            hdr = f" {'ID':<8} {'TIME':<19} {'CLIENT IP':<15} {'METH':<5} {'ACTION':<7} {'LAT(µs)':<9} {'RULE':<14} {'PATH'}"
            safe_addstr(stdscr, 8, 0, hdr, curses.color_pair(10) | curses.A_BOLD)
            if len(hdr) + len(pos_str) < max_x:
                safe_addstr(stdscr, 8, max_x - len(pos_str), pos_str, curses.color_pair(10) | curses.A_BOLD)

            # --- REQUEST LOG FEED (Line 9 onwards) WITH VIEWPORT SCROLL ---
            visible_records = self.records_cache[self.scroll_offset : self.scroll_offset + table_height]

            for i, rec in enumerate(visible_records):
                actual_idx = self.scroll_offset + i
                req_id = (rec["request_id"] or "")[:8]
                ts = (rec["timestamp"] or "")[:19]
                ip = (rec["client_ip"] or "127.0.0.1")[:15]
                meth = (rec["method"] or "GET")[:5]
                act = rec["action"] or "ALLOW"
                lat = f"{rec['latency_us'] or 0.0:7.1f}"
                rule = (rec["matched_rules"] or rec["category"] or "-")[:14]
                path = rec["path"] or "/"

                line = f" {req_id:<8} {ts:<19} {ip:<15} {meth:<5} {act:<7} {lat:<9} {rule:<14} {path}"

                is_selected = (actual_idx == self.selected_idx)
                
                # Highlight colors based on verdict
                if act.upper() == "BLOCK":
                    attr = curses.color_pair(8) if is_selected else curses.color_pair(3) | curses.A_BOLD
                else:
                    attr = curses.color_pair(9) if is_selected else curses.color_pair(1)

                safe_addstr(stdscr, row_y + i, 0, line, attr)

            # --- DETAIL MODAL (If Enter or 'd' is pressed) WITH INTERNAL SCROLL ---
            if self.show_detail and self.records_cache and self.selected_idx < len(self.records_cache):
                rec = self.records_cache[self.selected_idx]
                box_h = min(22, max(6, max_y - 4))
                box_w = min(100, max(20, max_x - 6))
                box_y = max(2, (max_y - box_h) // 2)
                box_x = max(2, (max_x - box_w) // 2)

                # Modal background
                for by in range(box_y, box_y + box_h):
                    safe_addstr(stdscr, by, box_x, " " * (box_w - 1), curses.color_pair(10))
                
                safe_addstr(stdscr, box_y, box_x + 2, f" FORMAL CAUSAL PROOF AUDIT :: [{rec['request_id']}] ", curses.color_pair(10) | curses.A_BOLD)
                safe_addstr(stdscr, box_y + 2, box_x + 2, f"Client IP : {rec['client_ip']}  |  Timestamp: {rec['timestamp']}", curses.color_pair(10))
                safe_addstr(stdscr, box_y + 3, box_x + 2, f"Endpoint  : {rec['method']} {rec['path']}", curses.color_pair(10))
                safe_addstr(stdscr, box_y + 4, box_x + 2, f"Verdict   : {rec['action']}  |  Category: {rec['category']}  |  Latency: {rec['latency_us']:.2f} µs", curses.color_pair(10) | curses.A_BOLD)
                safe_addstr(stdscr, box_y + 5, box_x + 2, f"Rule ID   : {rec['matched_rules']}", curses.color_pair(10) | curses.A_BOLD)
                safe_addstr(stdscr, box_y + 6, box_x + 2, "─" * max(0, box_w - 4), curses.color_pair(10))
                
                # Causal Proof Box with scroll
                proof_text = rec["causal_proof"] or "No proof attached (legitimate traffic passing SIMD invariants)."
                proof_lines = proof_text.splitlines()
                max_lines = max(1, box_h - 9)
                max_modal_scroll = max(0, len(proof_lines) - max_lines)
                self.modal_scroll_offset = max(0, min(self.modal_scroll_offset, max_modal_scroll))

                visible_proof = proof_lines[self.modal_scroll_offset : self.modal_scroll_offset + max_lines]
                for py, pl in enumerate(visible_proof):
                    safe_addstr(stdscr, box_y + 7 + py, box_x + 2, pl[:max(0, box_w - 4)], curses.color_pair(10))

                scroll_hint = f" [{self.modal_scroll_offset + 1}-{min(len(proof_lines), self.modal_scroll_offset + max_lines)}/{len(proof_lines)}] " if len(proof_lines) > max_lines else ""
                close_hint = f" [ESC / Enter] Close Detail {scroll_hint}"
                safe_addstr(stdscr, box_y + box_h - 1, box_x + 2, close_hint, curses.color_pair(7) | curses.A_BOLD)

            # --- BOTTOM TOOLBAR (htop style) ---
            bar_y = max_y - 1
            f_keys = [
                ("q", "Quit"),
                ("b", "Toggle Block/All"),
                ("p", "Pause"),
                ("d/↵", "Proof"),
                ("↑/↓/PgUp/PgDn", "Scroll"),
                ("r", "Refresh"),
                ("+/-", "Speed"),
            ]
            # Clear bottom toolbar without touching last cell
            safe_addstr(stdscr, bar_y, 0, " " * (max_x - 1), curses.color_pair(7))
            cur_x = 1
            for k, desc in f_keys:
                if cur_x >= max_x - 6:
                    break
                key_text = f" {k} "
                safe_addstr(stdscr, bar_y, cur_x, key_text, curses.color_pair(10) | curses.A_BOLD)
                cur_x += len(key_text)
                desc_text = f"{desc} "
                safe_addstr(stdscr, bar_y, cur_x, desc_text, curses.color_pair(7))
                cur_x += len(desc_text) + 1

            try:
                stdscr.refresh()
            except curses.error:
                pass

            # --- INPUT HANDLING WITH COMPLETE SCROLL SUPPORT ---
            try:
                ch = stdscr.getch()
            except Exception:
                ch = -1

            if ch == -1:
                pass
            elif self.show_detail:
                # Navigation within modal
                if ch in (curses.KEY_UP, ord('k')):
                    if self.modal_scroll_offset > 0:
                        self.modal_scroll_offset -= 1
                elif ch in (curses.KEY_DOWN, ord('j')):
                    self.modal_scroll_offset += 1
                elif ch in (curses.KEY_PPAGE,):
                    self.modal_scroll_offset = max(0, self.modal_scroll_offset - 8)
                elif ch in (curses.KEY_NPAGE,):
                    self.modal_scroll_offset += 8
                elif ch in (10, 13, 27, ord('d'), ord('D'), ord('q'), ord('Q')):
                    self.show_detail = False
            else:
                total_recs = len(self.records_cache)
                if ch in (ord('q'), ord('Q')):
                    break
                elif ch in (ord('p'), ord('P')):
                    self.paused = not self.paused
                elif ch in (ord('b'), ord('B')):
                    self.filter_mode = "BLOCK" if self.filter_mode == "ALL" else "ALL"
                    self.selected_idx = 0
                    self.scroll_offset = 0
                    last_tick = 0
                elif ch in (ord('r'), ord('R')):
                    last_tick = 0
                elif ch in (curses.KEY_UP, ord('k')):
                    if self.selected_idx > 0:
                        self.selected_idx -= 1
                elif ch in (curses.KEY_DOWN, ord('j')):
                    if self.selected_idx < total_recs - 1:
                        self.selected_idx += 1
                elif ch in (curses.KEY_PPAGE, 21):  # PgUp or Ctrl+U
                    page_step = max(1, table_height - 1)
                    self.selected_idx = max(0, self.selected_idx - page_step)
                elif ch in (curses.KEY_NPAGE, 4):   # PgDn or Ctrl+D
                    page_step = max(1, table_height - 1)
                    if total_recs > 0:
                        self.selected_idx = min(total_recs - 1, self.selected_idx + page_step)
                elif ch in (curses.KEY_HOME, ord('g')):
                    self.selected_idx = 0
                elif ch in (curses.KEY_END, ord('G')):
                    if total_recs > 0:
                        self.selected_idx = total_recs - 1
                elif ch in (10, 13, ord('d'), ord('D')):  # Enter or 'd'
                    if total_recs > 0:
                        self.show_detail = not self.show_detail
                        self.modal_scroll_offset = 0
                elif ch == 27:  # ESC
                    break
                elif ch in (ord('+'), ord('=')):
                    self.refresh_rate = max(0.2, self.refresh_rate - 0.2)
                elif ch in (ord('-'), ord('_')):
                    self.refresh_rate = min(5.0, self.refresh_rate + 0.5)
                elif ch == curses.KEY_MOUSE:
                    try:
                        _, _, _, _, bstate = curses.getmouse()
                        # Mouse wheel up / down support
                        if bstate & getattr(curses, "BUTTON4_PRESSED", 0x80000) or bstate & 0x10000:
                            self.selected_idx = max(0, self.selected_idx - 3)
                        elif bstate & getattr(curses, "BUTTON5_PRESSED", 0x800000) or bstate & 0x200000:
                            if total_recs > 0:
                                self.selected_idx = min(total_recs - 1, self.selected_idx + 3)
                    except Exception:
                        pass

def main():
    parser = argparse.ArgumentParser(
        description="GUARDIAN-TOP: Real-Time Interactive Monitor for Guardian WAF",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--db",
        "-d",
        help="Path to SQLite audit ledger database file (waf_ledger.db)",
        default=None,
    )
    parser.add_argument(
        "--rate",
        "-r",
        type=float,
        help="Refresh interval in seconds",
        default=1.0,
    )
    parser.add_argument(
        "--blocks-only",
        "-b",
        action="store_true",
        help="Start by displaying only blocked requests",
    )
    args = parser.parse_args()

    db_path = find_database(args.db)
    if not db_path:
        print("\n❌ Error: Guardian WAF audit ledger database (waf_ledger.db) not found.")
        print("   Searched paths:")
        for p in DEFAULT_DB_PATHS:
            print(f"     • {p}")
        print("\n   Specify the explicit path with:")
        print("     satguardian-top --db /var/lib/satguardian/waf_ledger.db\n")
        sys.exit(1)

    app = SatguardianTop(db_path, refresh_rate=args.rate)
    if args.blocks_only:
        app.filter_mode = "BLOCK"

    try:
        curses.wrapper(app.run)
    except KeyboardInterrupt:
        pass
    finally:
        print("\n[GUARDIAN-TOP] Monitor terminated. Guardian WAF continues running in the background.")

if __name__ == "__main__":
    main()
