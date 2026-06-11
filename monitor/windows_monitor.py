# monitor/windows_monitor.py
import platform, time, random
from collections import defaultdict

EVENT_MAP = {4625:"fail_login",4624:"login_success",4672:"admin_access",
             4688:"process_create",4698:"scheduled_task",4720:"account_created",
             7045:"service_installed",1102:"log_cleared",4719:"audit_policy_change"}
HIGH_RISK = {4672,4698,7045,4720,1102}
ATKIPS    = ["45.33.32.156","185.220.101.45","91.108.4.180","192.168.99.254","10.0.0.50"]
USERS     = ["admin","administrator","root","svc_backup","jsmith","guest"]

class WindowsMonitor:
    def __init__(self):
        self.last_read    = time.time()-300
        self.event_counts = defaultdict(int)
        self._ok = self._check()

    def _check(self):
        if platform.system() != "Windows": return False
        try: import win32evtlog; return True
        except ImportError: return False

    def collect(self):
        if self._ok: return self._real()
        return self._sim()

    def _real(self):
        import win32evtlog, win32con
        evts = []
        try:
            h = win32evtlog.OpenEventLog("localhost","Security")
            flags = win32con.EVENTLOG_BACKWARDS_READ | win32con.EVENTLOG_SEQUENTIAL_READ
            for ev in win32evtlog.ReadEventLog(h, flags, 0):
                try: ts = ev.TimeGenerated.timestamp()
                except Exception:
                    import calendar; ts = calendar.timegm(ev.TimeGenerated.timetuple())
                if ts <= self.last_read: continue
                eid = ev.EventID & 0xFFFF
                if eid not in EVENT_MAP: continue
                s = ev.StringInserts or []
                evts.append({
                    "type":     EVENT_MAP[eid],
                    "ip":       (s[18] if len(s)>18 else "local"),
                    "username": (s[5]  if len(s)>5  else "unknown"),
                    "event_id": eid, "timestamp": ts,
                    "source":   "windows_event_log",
                    "severity": "HIGH" if eid in HIGH_RISK else "INFO"
                })
            win32evtlog.CloseEventLog(h)
            self.last_read = time.time()
        except Exception: pass
        return evts

    def _sim(self):
        evts = []; now = time.time()
        if random.random() < 0.6:
            ip = random.choice(ATKIPS)
            for i in range(random.randint(2,6)):
                evts.append({"type":"fail_login","ip":ip,"username":random.choice(USERS),
                              "event_id":4625,"timestamp":now-i*3,"source":"simulation","severity":"MEDIUM"})
        if random.random() < 0.2:
            evts.append({"type":"admin_access","ip":random.choice(ATKIPS),"username":random.choice(USERS),
                         "event_id":4672,"timestamp":now,"source":"simulation","severity":"HIGH"})
        return evts
