# pyrefly: ignore [missing-import]
from pymongo import MongoClient
import json
c = MongoClient('mongodb://localhost:27017/')
db = c['IDS']
logs = list(db['batch_logs'].find({}, {'_id': 0, 'XAI_Explanation': 0, 'XAI_Timestamp': 0, 'XAI_Source': 0}))
ips = {}
for l in logs:
    ip = l.get('Source_IP', '?')
    if ip not in ips:
        ips[ip] = {'count': 0, 'decisions': set(), 'attacks': set(), 'risks': [], 'pps': [], 'mitm': []}
    ips[ip]['count'] += 1
    ips[ip]['decisions'].add(l.get('Decision', '?'))
    ips[ip]['attacks'].add(l.get('Attack_Type', '?'))
    ips[ip]['risks'].append(l.get('Final_Risk', 0))
    ips[ip]['pps'].append(l.get('PPS', 0))
    ips[ip]['mitm'].append(l.get('MITM_Risk', 0))

print(f'Total logs: {len(logs)}')
print(f'Unique IPs: {len(ips)}')
print()
for ip, d in sorted(ips.items(), key=lambda x: max(x[1]['risks']), reverse=True):
    avg_r = sum(d['risks']) / len(d['risks'])
    print(f"{ip}: logs={d['count']} max_risk={max(d['risks']):.2f} avg_risk={avg_r:.3f} max_pps={max(d['pps']):.1f} max_mitm={max(d['mitm']):.2f} decisions={d['decisions']} attacks={d['attacks']}")
