# simulation/scenarios/credential_dumping.py  — T1003
import time, random

TOOLS = ["mimikatz.exe","wce.exe","pwdump7.exe","LaZagne.exe","Rubeus.exe"]
CMDS  = ["sekurlsa::logonpasswords","lsadump::sam","sekurlsa::wdigest",
         "procdump -ma lsass.exe","reg save HKLM\\SAM sam.hiv"]

def run(intensity="medium"):
    user = random.choice(["SYSTEM","Administrator","attacker"])
    ip   = random.choice(["45.33.32.156","192.168.99.254","local"])
    now  = time.time()
    n    = {"low":1,"medium":2,"high":4}.get(intensity, 2)
    events = []
    for tool in random.sample(TOOLS, min(n, len(TOOLS))):
        events.append({"type":"suspicious_process","ip":"local","username":user,
                       "timestamp":now-random.randint(5,30),"source":"simulation",
                       "severity":"CRITICAL","process":tool,
                       "detail":f"Credential theft tool: {tool}"})
    for cmd in random.sample(CMDS, min(n, len(CMDS))):
        events.append({"type":"admin_access","ip":"local","username":user,
                       "timestamp":now-random.randint(1,10),"source":"simulation",
                       "severity":"CRITICAL","command":cmd})
    return {"technique_id":"T1003","technique_name":"Credential Dumping",
            "tactic":"Credential Access","severity":"CRITICAL","intensity":intensity,
            "target_user":user,"event_count":len(events),"events":events,
            "description":f"Simulated credential dumping using {n} tools/commands"}
