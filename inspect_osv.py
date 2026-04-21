import json

data = json.load(open('/tmp/osv_sample.json'))
print(f"Total vulns: {len(data['vulns'])}")
for v in data['vulns'][:3]:
    print(f"\nID: {v['id']}")
    print(f"  aliases: {v.get('aliases', [])}")
    print(f"  severity: {v.get('severity', [])}")
    db = v.get('database_specific', {})
    print(f"  database_specific keys: {list(db.keys())}")
    aff = v.get('affected', [{}])[0] if v.get('affected') else {}
    eco = aff.get('ecosystem_specific', {})
    print(f"  ecosystem_specific: {eco}")
