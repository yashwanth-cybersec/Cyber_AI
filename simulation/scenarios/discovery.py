# simulation/scenarios/discovery.py  — T1082
import time, random

ENUM_CMDS = ["systeminfo","whoami /all","net user","tasklist","netstat -ano",
             "ipconfig /all","arp -a","route print","net localgroup administrators"]

def run(intensity="medium"):
    user = random.choice(["attacker","jsmith","SYSTEM"])
    ip   = random.choice(["45.33.32.156","local","192.168.99.254"])
    now  = time.time()
    n    = {"low":3,"medium":6,"high":9}.get(intensity, 6)
    cmds = random.sample(ENUM_CMDS, min(n, len(ENUM_CMDS)))
    events = [{"type":"process_create","ip":"local","username":user,
               "timestamp":now-i*random.uniform(2,8),"source":"simulation",
               "severity":"MEDIUM","process":"cmd.exe","cmdline":cmd}
              for i, cmd in enumerate(cmds)]
    return {"technique_id":"T1082","technique_name":"System Discovery",
            "tactic":"Discovery","severity":"MEDIUM","intensity":intensity,
            "target_user":user,"event_count":len(events),"events":events,
            "description":f"Simulated {n} recon/enumeration commands"}
