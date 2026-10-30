"""Tests exercise local server and evidence state, not Windows-native APIs."""
import json
import sys
import unittest
from pathlib import Path
from datetime import datetime,timezone,timedelta
from urllib.request import urlopen,Request
from urllib.error import HTTPError

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from telemetry import WindowsTelemetry, derive, demo_sensors, SENSOR_GROUPS,age_seconds
from launch import start_server
from threading import Thread

class TelemetryTests(unittest.TestCase):
    def test_all_sensor_names_declared(self):
        self.assertEqual(len(sum(SENSOR_GROUPS.values(),[])),19)
        self.assertEqual(len(set(sum(SENSOR_GROUPS.values(),[]))),19)
    def test_demo_is_explicit(self):
        t=WindowsTelemetry(demo=True);t.start();shot=t.snapshot()
        self.assertTrue(shot['demo'])
        self.assertEqual(shot['derived']['coverage']['ok'],19)
        self.assertTrue(all('SYNTHETIC' in x['source'] for x in shot['sensors'].values()))
        t.stop()
    def test_alert_on_disabled_realtime(self):
        d=demo_sensors();d['defender']['data']['real_time']=False
        output=derive(d)
        self.assertTrue(any('Real-time' in a['title'] for a in output['alerts']))
    def test_missing_sensor_not_zero(self):
        output=derive({})
        self.assertEqual(output['coverage']['ok'],0)
        self.assertEqual(output['coverage']['starting'],19)
    def test_expired_sensor_is_stale(self):
        d=demo_sensors();d['system']['collected_at']=(datetime.now(timezone.utc)-timedelta(days=3)).isoformat()
        output=derive(d)
        self.assertEqual(output['coverage']['stale'],1)
    def test_collector_error_marks_previous_evidence_stale(self):
        t=WindowsTelemetry(demo=True);t.start();t._mode['fast']['state']='error'
        shot=t.snapshot()
        self.assertEqual(shot['sensors']['system']['state'],'stale')
        self.assertIn('failed',shot['sensors']['system']['reason'])
        t.stop()
    def test_event_truncation_alert(self):
        d=demo_sensors();d['security_events']['data']['truncated']=True
        self.assertTrue(any('cap' in x['title'] for x in derive(d)['alerts']))
    def test_unknown_is_not_false(self):
        d=demo_sensors();d['defender']={'state':'unavailable','reason':'access denied'}
        self.assertFalse(any(x['sensor']=='defender' for x in derive(d)['alerts']))
    def test_no_synthetic_production_on_nonwindows(self):
        if sys.platform!='win32':
            t=WindowsTelemetry();t.start();s=t.snapshot()
            self.assertFalse(s['demo'])
            self.assertEqual(s['derived']['coverage']['ok'],0)
            self.assertEqual(s['derived']['coverage']['unavailable'],19)
            t.stop()
    def test_http_api_readonly_and_local(self):
        t=WindowsTelemetry(demo=True);t.start()
        server=start_server(t)
        th=Thread(target=server.serve_forever,daemon=True);th.start()
        url=f'http://127.0.0.1:{server.server_port}'
        try:
            with urlopen(url+'/api/snapshot') as response:
                self.assertEqual(response.status,200)
                x=json.load(response)
                self.assertEqual(x['schema'],'lattice.dashboard.v1')
                self.assertEqual(response.headers.get('Access-Control-Allow-Origin'),None)
            with self.assertRaises(HTTPError) as e:
                urlopen(Request(url+'/api/snapshot',method='POST',data=b'hi'))
            self.assertEqual(e.exception.code,405)
            req=Request(url+'/',headers={'Host':f'evilhacker.example:{server.server_port}'})
            with self.assertRaises(HTTPError) as e:urlopen(req)
            self.assertEqual(e.exception.code,403)
            with self.assertRaises(HTTPError):urlopen(url+'/../../foo')
        finally:
            server.shutdown();server.server_close();t.stop()

if __name__=='__main__':unittest.main()
