# monitor/process_monitor.py
import time
from collections import defaultdict
try:
    import psutil
    OK = True
except ImportError:
    OK = False

SUS_NAMES = {"mimikatz","wce","pwdump","netcat","nc.exe","ncat","msfconsole",
             "psexec","paexec","xmrig","minerd","lazagne","rubeus"}
SUS_DIRS  = ["\\temp\\","\\tmp\\","\\appdata\\local\\temp\\","\\users\\public\\","/tmp/","/var/tmp/"]
SUS_CHAINS= [("winword.exe","cmd.exe"),("excel.exe","powershell.exe"),
             ("outlook.exe","cmd.exe"),("explorer.exe","powershell.exe")]

class ProcessMonitor:
    def __init__(self):
        self.known_pids    = set(psutil.pids()) if OK else set()
        self.cpu_baselines = {}
        self.event_counts  = defaultdict(int)

    def collect(self):
        if not OK: return []
        ev = []
        ev.extend(self._new_procs())
        ev.extend(self._sus_names())
        ev.extend(self._cpu_spikes())
        ev.extend(self._chains())
        self.known_pids = set(psutil.pids())
        return ev

    def _new_procs(self):
        ev = []
        for pid in set(psutil.pids()) - self.known_pids:
            try:
                p = psutil.Process(pid)
                name = p.name().lower(); exe = p.exe() or ""
                if any(s in name for s in SUS_NAMES) or any(d in exe.lower() for d in SUS_DIRS):
                    ev.append({"type":"process_create","ip":"local","username":self._user(p),
                               "pid":pid,"process":name,"exe":exe[:80],"source":"process_monitor",
                               "severity":"HIGH","timestamp":time.time()})
            except Exception: pass
        return ev

    def _sus_names(self):
        ev = []
        for p in psutil.process_iter(["pid","name","exe","username"]):
            try:
                name = (p.info["name"] or "").lower(); exe = (p.info["exe"] or "").lower()
                if any(s in name or s in exe for s in SUS_NAMES):
                    ev.append({"type":"suspicious_process","ip":"local",
                               "username":p.info.get("username") or "unknown",
                               "pid":p.info["pid"],"process":name,"source":"process_monitor",
                               "severity":"CRITICAL","timestamp":time.time()})
            except Exception: pass
        return ev

    def _cpu_spikes(self):
        ev = []
        for p in psutil.process_iter(["pid","name","username"]):
            try:
                cpu = p.cpu_percent(interval=0.05); pid = p.info["pid"]
                if pid not in self.cpu_baselines: self.cpu_baselines[pid] = cpu; continue
                base = self.cpu_baselines[pid]
                self.cpu_baselines[pid] = base*0.85 + cpu*0.15
                if cpu > 50 and cpu > base*3 and base > 5:
                    ev.append({"type":"cpu_spike","ip":"local","username":p.info.get("username") or "unknown",
                               "pid":pid,"process":p.info["name"],"cpu":round(cpu,1),
                               "source":"process_monitor","severity":"MEDIUM","timestamp":time.time()})
            except Exception: pass
        return ev

    def _chains(self):
        ev = []
        try:
            procs = {p.pid: p.info for p in psutil.process_iter(["pid","name","ppid","username"])}
            for pid, info in procs.items():
                child = (info.get("name") or "").lower(); ppid = info.get("ppid")
                if ppid and ppid in procs:
                    parent = (procs[ppid].get("name") or "").lower()
                    for ps, cs in SUS_CHAINS:
                        if ps in parent and cs in child:
                            ev.append({"type":"suspicious_process","ip":"local",
                                       "username":info.get("username") or "unknown",
                                       "pid":pid,"process":child,"parent":parent,
                                       "detail":f"{parent} spawned {child}",
                                       "source":"process_monitor","severity":"CRITICAL","timestamp":time.time()})
        except Exception: pass
        return ev

    def _user(self, p):
        try: return p.username() or "unknown"
        except Exception: return "unknown"
