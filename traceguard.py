"""TraceGuard: offline SOC log triage, Python standard library only."""
import argparse
import hashlib
import ipaddress
import json
import sqlite3
import sys
from collections import defaultdict, deque
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
VERSION = '1.0.0'
STATUSES = ('New','Investigating','Closed — benign','Closed — confirmed')
RULES = {
 'TG-001': {'name':'Repeated authentication failures','severity':'High','technique':'T1110', 'threshold':10, 'seconds':300, 'description':'10 failed logins for one source IP, host and user in a rolling five-minute window.'},
 'TG-002': {'name':'Possible password spraying','severity':'High','technique':'T1110.003','threshold':10,'seconds':600,'description':'Failures against 10 distinct users from one source IP across imported hosts in ten minutes. Password reuse cannot be established from this schema.'},
 'TG-003': {'name':'Success after repeated failures','severity':'Critical','technique':'T1078','threshold':5,'seconds':600,'description':'A successful login follows at least five failures for the same source IP, host and user in ten minutes. This is an investigation lead, not proof of compromise.'},
 'TG-004': {'name':'Possible port probing','severity':'Medium','technique':'T1046','threshold':20,'seconds':300,'description':'Connections to 20 distinct destination ports on one host from a source IP in five minutes. Authorized inventory tools may trigger this rule.'}
}

def utcnow():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')

def digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()

def stamp(value):
    if not isinstance(value,str):
        raise ValueError('timestamp must be an ISO 8601 string with timezone')
    t=datetime.fromisoformat(value.replace('Z','+00:00'))
    if t.tzinfo is None:
        raise ValueError('timestamp requires a timezone, e.g. 2026-11-17T09:00:00Z')
    return t.astimezone(timezone.utc)

def clean(value,field,required=True):
    if not isinstance(value,str) or len(value)>200 or any(ord(c)<32 for c in value):
        raise ValueError(f'{field} must be text up to 200 characters without control characters')
    value=value.strip()
    if required and not value:
        raise ValueError(f'{field} is required')
    return value

def parse_events(raw):
    if len(raw.encode('utf-8'))>20_000_000:
        raise ValueError('Input limit is 20 MB')
    events={}
    count=0
    for line_number,line in enumerate(raw.lstrip('\ufeff').splitlines(),1):
        if not line.strip():
            continue
        count+=1
        if count>50000:
            raise ValueError('Input limit is 50,000 rows')
        try:
            value=json.loads(line)
            if not isinstance(value,dict):
                raise ValueError('each JSONL row must be an object')
            kind=value.get('event_type')
            if kind not in ('auth_failure','auth_success','network_connection'):
                raise ValueError('unsupported event_type')
            event={'timestamp':stamp(value['timestamp']).isoformat(),'event_type':kind,
                   'host':clean(value['host'],'host'),
                   'src_ip':str(ipaddress.ip_address(value['src_ip'])),
                   'user':clean(value.get('user',''),'user',required=kind!='network_connection')}
            if kind=='network_connection':
                port=value['dst_port']
                if type(port) is not int or not 0<=port<=65535:
                    raise ValueError('dst_port must be an integer from 0 to 65535')
                event['dst_port']=port
            event['id']=digest(event)
            events[event['id']]=event
        except (ValueError,KeyError,TypeError) as exc:
            raise ValueError(f'Line {line_number}: {exc}') from None
    if not events:
        raise ValueError('No events supplied')
    return sorted(events.values(),key=lambda e:(e['timestamp'],e['id']))

def detect(events):
    """Pure deterministic rolling-window engine; no network access or code evaluation."""
    queues={r:defaultdict(deque) for r in RULES}
    emitted={}
    alerts=[]
    def window(rule,key,event):
        queue=queues[rule][key]
        current=stamp(event['timestamp'])
        cutoff=current-timedelta(seconds=RULES[rule]['seconds'])
        while queue and stamp(queue[0]['timestamp'])<cutoff:
            queue.popleft()
        return queue,current
    def emit(rule,key,event,evidence,count):
        current=stamp(event['timestamp'])
        last=emitted.get((rule,key))
        if last is not None and (current-last).total_seconds()<RULES[rule]['seconds']:
            return
        emitted[(rule,key)]=current
        cfg=RULES[rule]
        alerts.append({'id':digest([rule,key,event['id']])[:24], 'rule':rule,'name':cfg['name'],
                       'severity':cfg['severity'],'technique':cfg['technique'],'timestamp':event['timestamp'],
                       'src_ip':event['src_ip'],'host':event['host'],'user':event['user'],
                       'observed_count':count,'evidence_ids':[e['id'] for e in evidence][-100:],
                       'evidence_total':len(evidence),'reason':cfg['description'],
                       'scope':list(key),'rule_version':VERSION})
    for event in sorted({e['id']:e for e in events}.values(),key=lambda e:(e['timestamp'],e['id'])):
        key=(event['src_ip'],event['host'],event['user'])
        kind=event['event_type']
        if kind=='auth_failure':
            for rule,group in [('TG-001',key),('TG-002',(event['src_ip'],)),('TG-003',key)]:
                queue,_=window(rule,group,event)
                queue.append(event)
                if rule=='TG-001' and len(queue)>=RULES[rule]['threshold']:
                    emit(rule,group,event,list(queue),len(queue))
                if rule=='TG-002':
                    users=len({e['user'] for e in queue})
                    if users>=RULES[rule]['threshold']:
                        emit(rule,group,event,list(queue),users)
        elif kind=='auth_success':
            queue,_=window('TG-003',key,event)
            if len(queue)>=RULES['TG-003']['threshold']:
                emit('TG-003',key,event,list(queue)+[event],len(queue))
            queue.clear()
        else:
            group=(event['src_ip'],event['host'])
            queue,_=window('TG-004',group,event)
            queue.append(event)
            ports=len({e['dst_port'] for e in queue})
            if ports>=RULES['TG-004']['threshold']:
                emit('TG-004',group,event,list(queue),ports)
    rank={'Critical':0,'High':1,'Medium':2}
    return sorted(alerts,key=lambda a:(rank[a['severity']],a['timestamp'],a['id']))

@contextmanager
def database(path):
    Path(path).parent.mkdir(parents=True,exist_ok=True)
    conn=sqlite3.connect(path,timeout=10)
    conn.row_factory=sqlite3.Row
    try:
        with conn:
            conn.executescript('''CREATE TABLE IF NOT EXISTS events(id TEXT PRIMARY KEY, data TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS cases(id TEXT PRIMARY KEY,status TEXT NOT NULL,notes TEXT NOT NULL,updated_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS history(id INTEGER PRIMARY KEY,at TEXT NOT NULL,action TEXT NOT NULL,detail TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL);''')
            yield conn
    finally:
        conn.close()

def ingest(db_path,events,synthetic=False):
    with database(db_path) as conn:
        current={r[0] for r in conn.execute('SELECT id FROM events')}
        if len(current|{e['id'] for e in events})>50000:
            raise ValueError('Workspace limit is 50,000 unique events; start another workspace')
        new=sum(e['id'] not in current for e in events)
        if not current or not synthetic:
            conn.execute('INSERT OR REPLACE INTO metadata VALUES(?,?)',('synthetic',str(bool(synthetic))))
        conn.executemany('INSERT OR IGNORE INTO events VALUES(?,?)',[(e['id'],json.dumps(e)) for e in events])
        conn.execute('INSERT INTO history(at,action,detail) VALUES(?,?,?)',(utcnow(),'import',json.dumps({'received_unique':len(events),'new_events':new})))
    return new

def state(db_path):
    with database(db_path) as conn:
        events=[json.loads(r['data']) for r in conn.execute('SELECT * FROM events')]
        cases={r['id']:dict(r) for r in conn.execute('SELECT * FROM cases')}
        history=[dict(r) for r in conn.execute('SELECT * FROM history ORDER BY id DESC LIMIT 100')]
        provenance=conn.execute("SELECT value FROM metadata WHERE key='synthetic'").fetchone()
    alerts=detect(events)
    for alert in alerts:
        alert.update(cases.get(alert['id'],{'status':'New','notes':'','updated_at':None}))
    return {'project':'TraceGuard','version':VERSION,'generated_at':utcnow(),'synthetic':bool(provenance and provenance[0]=='True'),
            'events':sorted(events,key=lambda e:(e['timestamp'],e['id'])), 'alerts':alerts,'history':history,
            'rules':RULES,'limitations':'Heuristic alerts require analyst validation. ATT&CK mappings are contextual, not confirmation of an attack.'}

def update_case(db_path,ident,status,notes):
    if status not in STATUSES:
        raise ValueError('Unsupported status')
    if not isinstance(notes,str) or len(notes)>4000:
        raise ValueError('Notes limit is 4,000 characters')
    if ident not in {a['id'] for a in state(db_path)['alerts']}:
        raise ValueError('Alert does not exist in the current analysis')
    with database(db_path) as conn:
        conn.execute('INSERT OR REPLACE INTO cases VALUES(?,?,?,?)',(ident,status,notes,utcnow()))
        conn.execute('INSERT INTO history(at,action,detail) VALUES(?,?,?)',(utcnow(),'case',json.dumps({'id':ident,'status':status,'notes':notes})))

def report(db_path,output):
    snapshot=state(db_path)
    folder=Path(output)
    folder.mkdir(parents=True,exist_ok=True)
    (folder/'report.json').write_text(json.dumps(snapshot,indent=2),encoding='utf-8')
    # Escape HTML-significant characters in script data, including </script> and Unicode line separators.
    data=json.dumps(snapshot,ensure_ascii=True).replace('&','\\u0026').replace('<','\\u003c').replace('>','\\u003e')
    template=(ROOT/'web'/'report.html').read_text(encoding='utf-8')
    page=template.replace('/*__REPORT_DATA__*/',data)
    (folder/'report.html').write_text(page,encoding='utf-8')
    return folder/'report.html'

def demo_events():
    base=datetime(2026,11,17,9,0,tzinfo=timezone.utc)
    rows=[]
    def add(seconds,kind,ip,host,user='',port=None):
        row={'timestamp':(base+timedelta(seconds=seconds)).isoformat(),'event_type':kind,'src_ip':ip,'host':host,'user':user}
        if port is not None:row['dst_port']=port
        rows.append(row)
    for i in range(12):add(i*15,'auth_failure','192.0.2.10','demo-identity','demo-admin')
    add(190,'auth_success','192.0.2.10','demo-identity','demo-admin')
    for i in range(12):add(300+i*15,'auth_failure','198.51.100.20','demo-sso',f'demo-user-{i}')
    for i in range(25):add(700+i*3,'network_connection','203.0.113.30','demo-server',port=20+i)
    for i in range(18):add(1000+i*60,'auth_success','192.0.2.200','demo-office',f'demo-employee-{i%4}')
    return '\n'.join(json.dumps(e) for e in rows)+'\n'

def main(argv=None):
    parser=argparse.ArgumentParser(description='TraceGuard offline SOC log triage and investigation')
    parser.add_argument('--db',default=str(ROOT/'data'/'traceguard.db'),help='SQLite workspace; select a different path to isolate datasets')
    sub=parser.add_subparsers(dest='command',required=True)
    demo=sub.add_parser('demo',help='Analyze fictional demonstration events in an EMPTY workspace')
    demo.add_argument('--output',default=str(ROOT/'exports'))
    analyze=sub.add_parser('analyze',help='Import normalized JSONL and generate reports')
    analyze.add_argument('input',type=Path)
    analyze.add_argument('--output',default=str(ROOT/'exports'))
    sub.add_parser('cases',help='List current alerts and case status')
    case=sub.add_parser('case',help='Update a case; then regenerate reports')
    case.add_argument('id');case.add_argument('--status',required=True,choices=STATUSES)
    case.add_argument('--notes',default='');case.add_argument('--output',default=str(ROOT/'exports'))
    regenerate=sub.add_parser('report',help='Regenerate reports from the persisted workspace')
    regenerate.add_argument('--output',default=str(ROOT/'exports'))
    args=parser.parse_args(argv)
    try:
        if args.command=='demo':
            if state(args.db)['events']:
                raise ValueError('Demo requires an empty workspace; choose --db with a new path')
            ingest(args.db,parse_events(demo_events()),synthetic=True)
        elif args.command=='analyze':
            if args.input.stat().st_size>20_000_000:raise ValueError('Input limit is 20 MB')
            events=parse_events(args.input.read_text(encoding='utf-8-sig'))
            print(f'Imported {ingest(args.db,events)} new unique events.')
        elif args.command=='case':
            update_case(args.db,args.id,args.status,args.notes)
        elif args.command=='cases':
            for alert in state(args.db)['alerts']:
                print(f"{alert['id']} | {alert['severity']:8} | {alert['rule']} | {alert['status']} | {alert['src_ip']}")
            return 0
        path=report(args.db,args.output)
        snapshot=state(args.db)
        print(f"{len(snapshot['events'])} events; {len(snapshot['alerts'])} alerts. Open: {path.resolve()}")
        return 0
    except (ValueError,OSError,sqlite3.Error) as exc:
        print(f'Error: {exc}',file=sys.stderr)
        return 1

if __name__=='__main__':
    raise SystemExit(main())
