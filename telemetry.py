"""Windows PowerShell read-only telemetry bridge with bounded snapshots and observable failures.

No synthetic production measurements and no collection outside Windows.
"""
from __future__ import annotations
import concurrent.futures
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import threading
import time
from datetime import datetime, timezone
from typing import Any

BASE = Path(__file__).resolve().parent
MODES = {"fast": 12.0, "security": 90.0}
TIMEOUTS = {"fast": 33, "security": 75}
SENSOR_GROUPS = {
    "fast": ["system", "disks", "processes", "network"],
    "security": ["defender", "asr", "firewall", "secureboot", "tpm", "vbs", "bitlocker", "accounts", "hotfix", "security_events", "system_events", "defender_events", "services", "event_channels", "smb"],
}

def utc_now():
    return datetime.now(timezone.utc).isoformat()

def age_seconds(s: str | None) -> float | None:
    if not s:
        return None
    try:
        return max(0., (datetime.now(timezone.utc)-datetime.fromisoformat(s.replace('Z','+00:00'))).total_seconds())
    except (ValueError, TypeError):
        return None

def _datum(sensor: dict, key: str):
    return sensor.get('data', {}).get(key) if sensor.get('state') == 'ok' else None

def _count(data: dict, key: str) -> int:
    return int((data.get('counts') or {}).get(key, 0) or 0)

def derive(sensors: dict[str,dict]) -> dict:
    """Rules describe investigation triggers; no unsupported global security scores."""
    alerts=[]
    def add(priority,title,description,sensor):
        alerts.append({"priority":priority,"title":title,"description":description,"sensor":sensor})
    d=sensors.get('defender',{})
    if d.get('state')=='ok':
        if _datum(d,'antivirus_enabled') is False: add('attention','Defender antivirus reports disabled','Check whether another provider is intentionally managing protection.','defender')
        if _datum(d,'real_time') is False: add('attention','Real-time Defender protection reports disabled','Review the active security provider and protection policy.','defender')
        updated=age_seconds(_datum(d,'signature_updated'))
        if updated is not None and updated>7*86400: add('attention','Defender signature timestamp is over 7 days old','Age is not proof of ineffective malware detection.','defender')
    f=sensors.get('firewall',{})
    if f.get('state')=='ok':
        profiles=_datum(f,'profiles') or []
        for p in profiles:
            if p.get('enabled') is False:
                add('attention',f"Firewall {p.get('name','?')} profile is off",'Verify whether this profile is in use and whether the exception is intentional.','firewall')
    s=sensors.get('secureboot',{})
    if s.get('state')=='ok' and _datum(s,'enabled') is False:
        add('review','Secure Boot reports disabled','May be intentional for this platform; check applicable boot-trust requirements.','secureboot')
    b=sensors.get('bitlocker',{})
    if b.get('state')=='ok':
        for vol in (_datum(b,'volumes') or []):
            if str(vol.get('mount','')).upper().startswith('C:') and str(vol.get('protection','')).lower() in ('off','0'):
                add('review','OS-volume BitLocker protection reports off','Encryption requirements vary; inspect the volume protection status.','bitlocker')
    events=sensors.get('security_events',{})
    if events.get('state')=='ok':
        stats=events.get('data') or {}
        if _count(stats,'1102')>0: add('attention','Security audit log clear event observed','Windows Security event 1102 appears in the bounded 24-hour sample.','security_events')
        if _count(stats,'4719')>0: add('review','Audit policy change event observed','Security event 4719 appears in the bounded sample.','security_events')
        if _count(stats,'4625')>=10: add('review','At least 10 failed-logon events observed','Only events within the bounded query; this is not proof of attack.','security_events')
        if stats.get('truncated'): add('review','Security log sample reached its cap','Counts shown are lower bounds for the selected event IDs.','security_events')
    for sensor,identifier,label in [('system_events','7045','Service installation'),('defender_events','1116','Defender malware detection'),('defender_events','5007','Defender configuration change')]:
        e=sensors.get(sensor,{})
        if e.get('state')=='ok' and _count(e.get('data') or {},identifier)>0:
            add('review',f'{label} event observed',f'Event {identifier} was observed; review provenance before concluding malicious activity.',sensor)
    smb=sensors.get('smb',{})
    if smb.get('state')=='ok' and _datum(smb,'smb1_enabled') is True:
        add('review','SMB1 server protocol reports enabled','Review whether the legacy file-sharing protocol is required.','smb')
    channels=sensors.get('event_channels',{})
    if channels.get('state')=='ok':
        for channel in (_datum(channels,'channels') or []):
            if channel.get('name')=='Security' and channel.get('enabled') is False:
                add('attention','Windows Security event channel reports disabled','Event visibility is impaired; confirm channel configuration and policy.','event_channels')
    sys=sensors.get('system',{})
    if sys.get('state')=='ok':
        data=sys.get('data',{})
        total=data.get('memory_total_bytes') or 0
        used=data.get('memory_used_bytes') or 0
        if total>0 and used/total>0.93: add('attention','Physical memory usage over 93%','Resource pressure merits inspection.','system')
    net=sensors.get('network',{})
    if net.get('state')=='ok':
        binds=[v for v in (_datum(net,'listening') or []) if v.get('address') in ('0.0.0.0','::')]
        if binds: add('review',f'{len(binds)} sampled wildcard TCP listeners','Wildcard bind is not proof of remote reachability; firewall and interfaces matter.','network')
    gaps=[]; ready=0; stale=0; unavailable=0; starting=0
    for mode,keys in SENSOR_GROUPS.items():
        for name in keys:
            sensor=sensors.get(name) or {}
            status=sensor.get('state','starting')
            ttl=MODES[mode]*2 + TIMEOUTS[mode]
            age=age_seconds(sensor.get('collected_at'))
            if status=='ok' and (age is None or age>ttl):
                status='stale';stale+=1
            elif status=='ok':ready+=1
            elif status=='stale':stale+=1
            elif status=='starting': starting+=1
            else: unavailable+=1
            if status!='ok':
                gaps.append({"sensor":name,"state":status,"reason":str(sensor.get('reason') or 'No successful reading yet')[:180],"age_seconds":age})
    alerts.sort(key=lambda x:{'attention':0,'review':1}.get(x['priority'],2))
    return {"alerts":alerts[:40],"gaps":gaps,"coverage":{"ok":ready,"total":sum(map(len,SENSOR_GROUPS.values())),"unavailable":unavailable,"stale":stale,"starting":starting}}

class WindowsTelemetry:
    def __init__(self, demo=False):
        self.demo=demo
        self.windows=platform.system()=='Windows'
        self.power_shell=shutil.which('powershell.exe') or shutil.which('pwsh.exe') if self.windows else None
        self._lock=threading.RLock()
        self._mode={k:{'state':'starting','last_attempt':None,'last_success':None,'last_duration_ms':None,'error':None} for k in MODES}
        self._sensors={}
        self._history=[]
        self._stop=threading.Event()
        self._thread=None
        self._executor=concurrent.futures.ThreadPoolExecutor(max_workers=2,thread_name_prefix='lattice-collector')
        self._start_at=time.monotonic()
    def start(self):
        if self.demo:
            self._sensors=demo_sensors()
            for mode in self._mode:self._mode[mode].update({'state':'ok','last_success':utc_now()})
            return
        if not self.windows or not self.power_shell:
            reason='Only Windows is supported for real collectors' if not self.windows else 'Windows PowerShell not found'
            for mode,keys in SENSOR_GROUPS.items():
                self._mode[mode].update({'state':'unavailable','error':reason})
                for key in keys:self._sensors[key]={'state':'unavailable','reason':reason,'source':'Windows PowerShell','collected_at':utc_now()}
            return
        self._thread=threading.Thread(target=self._scheduler,daemon=True,name='lattice-scheduler');self._thread.start()
    def stop(self):
        self._stop.set()
        if self._thread:self._thread.join(timeout=1)
        self._executor.shutdown(wait=False,cancel_futures=True)
    def _scheduler(self):
        futures={};due={k:0 for k in MODES}
        while not self._stop.is_set():
            now=time.monotonic()
            for mode in MODES:
                fut=futures.get(mode)
                if fut is not None and fut.done():
                    try:self._accept(mode,fut.result())
                    except Exception as e:self._fail(mode,type(e).__name__+': '+str(e)[:200])
                    futures.pop(mode,None)
                if mode not in futures and now>=due[mode]:
                    futures[mode]=self._executor.submit(self._collect,mode)
                    with self._lock:self._mode[mode]['state']='collecting';self._mode[mode]['last_attempt']=utc_now()
                    due[mode]=now+MODES[mode]
            self._stop.wait(0.5)
    def _collect(self,mode):
        # Temporary output is deleted immediately after reading, even on failures.
        start=time.monotonic()
        with tempfile.TemporaryDirectory(prefix='lattice_') as td:
            out=Path(td)/'collector.json'
            args=[self.power_shell,'-NoLogo','-NoProfile','-NonInteractive','-File',str(BASE/'Collect-Lattice.ps1'),'-Mode',mode,'-OutputPath',str(out)]
            try:
                p=subprocess.run(args,capture_output=True,text=True,errors='replace',timeout=TIMEOUTS[mode],stdin=subprocess.DEVNULL,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
            except subprocess.TimeoutExpired:
                raise RuntimeError(f'{mode} collector exceeded {TIMEOUTS[mode]}s limit')
            if p.returncode!=0:raise RuntimeError(f'PowerShell exit {p.returncode}: {(p.stderr or p.stdout).strip()[-500:]}')
            if not out.exists():raise RuntimeError('PowerShell produced no snapshot file')
            if out.stat().st_size>2_000_000:raise RuntimeError('Collector output exceeds 2 MB safety cap')
            report=json.loads(out.read_text(encoding='utf-8-sig'))
        if report.get('schema')!='lattice.windows.collector.v1' or report.get('mode')!=mode or not isinstance(report.get('sensors'),dict):
            raise RuntimeError('Invalid collector schema or mode')
        return (report,round((time.monotonic()-start)*1000))
    def _accept(self,mode,result):
        report,duration_ms=result
        expected=SENSOR_GROUPS[mode]
        entries={name:report['sensors'].get(name,{'state':'unavailable','reason':'Collector did not return this sensor','source':'collector'}) for name in expected}
        with self._lock:
            self._sensors.update(entries)
            self._mode[mode].update({'state':'ok','last_success':utc_now(),'last_duration_ms':duration_ms,'error':None,'is_admin':report.get('is_admin')})
            system=self._sensors.get('system',{})
            network=self._sensors.get('network',{})
            if mode=='fast':
                d=system.get('data') or {};n=network.get('data') or {}
                mem=round(100*d['memory_used_bytes']/d['memory_total_bytes'],1) if d.get('memory_total_bytes') else None
                self._history.append({'time':utc_now(),'cpu':d.get('cpu_load_pct'),'memory':mem,'tcp':n.get('total')})
                self._history=self._history[-120:]
    def _fail(self,mode,reason):
        with self._lock:
            self._mode[mode].update({'state':'error','error':reason,'last_duration_ms':None})
            # Keep last successful values to show staleness, not pretend a failed poll was fresh.
            for key in SENSOR_GROUPS[mode]:
                if key not in self._sensors:
                    self._sensors[key]={'state':'unavailable','source':'collector','reason':reason[:180],'collected_at':utc_now()}
    def snapshot(self):
        with self._lock:
            sensors=json.loads(json.dumps(self._sensors))
            modes=json.loads(json.dumps(self._mode))
            history=self._history[-120:].copy()
        # Runtime status can supersede older successful evidence without destroying
        # raw data. The UI will not treat stale or failed-poll data as current.
        for mode, names in SENSOR_GROUPS.items():
            for name in names:
                entry=sensors.get(name)
                if not entry or entry.get('state')!='ok':
                    continue
                last_age=age_seconds(entry.get('collected_at'))
                if modes.get(mode,{}).get('state')=='error':
                    entry['state']='stale'
                    entry['reason']='Latest collector poll failed; previously successful evidence retained for inspection'
                elif last_age is None or last_age>MODES[mode]*2+TIMEOUTS[mode]:
                    entry['state']='stale'
                    entry['reason']='Sensor reading exceeded its allowed evidence age'
        derived=derive(sensors)
        return {'schema':'lattice.dashboard.v1','generated_at':utc_now(),'demo':self.demo,'platform':platform.system(),'collector_available':bool(self.power_shell) or self.demo,'uptime_seconds':round(time.monotonic()-self._start_at),'sensors':sensors,'modes':modes,'history':history,'derived':derived}

def demo_sensors():
    # Explicitly synthetic values, used only when application is started with --demo.
    now=utc_now()
    def item(data,source='SYNTHETIC DEMONSTRATION — not a Windows reading'):
        return {'state':'ok','collected_at':now,'source':source,'data':data}
    d={
        'system':item({'cpu_load_pct':24,'memory_total_bytes':34359738368,'memory_used_bytes':15032385536,'memory_free_bytes':19327352832,'uptime_seconds':201330,'os_caption':'Windows 11 [SYNTHETIC]','os_build':'DEMO','logical_processors':16}),
        'disks':item({'count':2,'volumes':[{'name':'C:','size_bytes':10**12,'free_bytes':380*10**9},{'name':'D:','size_bytes':2*10**12,'free_bytes':1540*10**9}]}),
        'processes':item({'count':176,'top_memory':[{'name':n,'pid':1000+i,'working_set_bytes':s,'cpu_seconds':7*i} for i,(n,s) in enumerate([('firefox',1210000000),('Code',834000000),('powershell',215000000),('explorer',148000000),('MsMpEng',199000000)])]}),
        'network':item({'total':92,'states':{'Listen':36,'Established':41,'TimeWait':15},'listening':[{'port':443,'address':'127.0.0.1','pid':172,'process':'local-tool'},{'port':5173,'address':'0.0.0.0','pid':423,'process':'example-app'}],'established':[{'remote':'203.0.113.12','remote_port':443,'pid':409,'process':'firefox'}],'adapters':[{'name':'Ethernet','status':'Up','link_speed':'1 Gbps'}]}),
        'defender':item({'antivirus_enabled':True,'real_time':True,'on_access':True,'tamper_protected':True,'signature_updated':now,'engine_version':'1.1 DEMO','signature_version':'DEMO'}),
        'asr':item({'rule_count':8,'mode_counts':{'Enabled':5,'AuditMode':3},'exclusion_path_count':1,'exclusion_process_count':0,'exclusion_extension_count':0}),
        'firewall':item({'profiles':[{'name':'Domain','enabled':True,'inbound':'Block','outbound':'Allow','log_blocked':'True'},{'name':'Private','enabled':True,'inbound':'Block','outbound':'Allow','log_blocked':'True'},{'name':'Public','enabled':True,'inbound':'Block','outbound':'Allow','log_blocked':'True'}],'active_networks':[{'network_category':'Private','interface_alias':'Ethernet'}],'enabled_rule_count':308,'rule_counts':{'Inbound_Allow':182,'Inbound_Block':26,'Outbound_Allow':87,'Outbound_Block':13}}),
        'secureboot':item({'enabled':True}),'tpm':item({'present':True,'ready':True,'enabled':True,'activated':True}),
        'vbs':item({'vbs_status':2,'security_services_running':[1,2],'credential_guard':True,'memory_integrity':True,'security_services_configured':[1,2]}),
        'bitlocker':item({'volumes':[{'mount':'C:','protection':'On','volume_status':'FullyEncrypted','encryption_pct':100,'lock_status':'Unlocked'}],'count':1}),
        'accounts':item({'local_user_count':4,'enabled_local_user_count':2,'local_admin_group_members':2}),
        'hotfix':item({'recent_hotfixes':[{'id':'KB-DEMO','installed':now}],'count_in_query':12}),
        'services':item({'services':[{'name':'WinDefend','state':'Running','start_type':'Automatic'},{'name':'MpsSvc','state':'Running','start_type':'Automatic'},{'name':'EventLog','state':'Running','start_type':'Automatic'},{'name':'wuauserv','state':'Stopped','start_type':'Manual'},{'name':'WinRM','state':'Stopped','start_type':'Manual'},{'name':'RemoteRegistry','state':'Stopped','start_type':'Disabled'},{'name':'TermService','state':'Running','start_type':'Manual'},{'name':'LanmanServer','state':'Running','start_type':'Automatic'}]}),
        'event_channels':item({'channels':[{'name':'Security','available':True,'enabled':True,'record_count':9000,'maximum_bytes':20971520,'log_mode':'Circular'},{'name':'System','available':True,'enabled':True,'record_count':8000,'maximum_bytes':20971520,'log_mode':'Circular'},{'name':'Microsoft-Windows-Windows Defender/Operational','available':True,'enabled':True,'record_count':3000,'maximum_bytes':15728640,'log_mode':'Circular'}]}),
        'smb':item({'smb1_enabled':False,'smb2_enabled':True,'signing_required':True,'encryption_supported':False}),
        'security_events':item({'window_hours':24,'sample_count':8,'sample_limit':250,'truncated':False,'counts':{'4625':4,'4688':4,'1102':0,'4719':0,'4720':0,'4732':0,'4698':0},'recent':[{'id':4625,'when':now,'level':'Information','provider':'Security Auditing'}]}),
        'system_events':item({'window_hours':24,'sample_count':1,'sample_limit':100,'truncated':False,'counts':{'7045':1},'recent':[{'id':7045,'when':now,'level':'Information','provider':'Service Control Manager'}]}),
        'defender_events':item({'window_hours':24,'sample_count':1,'sample_limit':100,'truncated':False,'counts':{'1116':0,'1117':0,'5007':1},'recent':[{'id':5007,'when':now,'level':'Information','provider':'Defender'}]})
    }
    return d
