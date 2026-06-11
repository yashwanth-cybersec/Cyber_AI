# simulation/scenarios/privilege_escalation.py  — T1548
import time, random

CMDS = ["sudo su -","whoami /priv","net localgroup administrators user /add",
        "chmod +s /bin/bash","runas /user:administrator cmd.exe"]

def run(intensity="medium"):
    user  = random.choice(["webuser","jsmith","dbuser","appservice"])
    now   = time.time()
    n     = {"low":1,"medium":2,"high":4}.get(intensity, 2)
    events = [{"type":"admin_access","ip":"local","username":user,
               "timestamp":now-i*3,"source":"simulation","severity":"HIGH",
               "command":random.choice(CMDS)} for i in range(n)]
    if intensity in ("medium","high"):
        events.append({"type":"process_create","ip":"local","username":user,
                       "timestamp":now,"source":"simulation","severity":"CRITICAL",
                       "process":"cmd.exe","cmdline":"cmd.exe /c whoami /priv"})
    return {"technique_id":"T1548","technique_name":"Privilege Escalation",
            "tactic":"Privilege Escalation","severity":"CRITICAL","intensity":intensity,
            "target_user":user,"event_count":len(events),"events":events,
            "description":f"Simulated privilege escalation by '{user}' using {n} commands"}
