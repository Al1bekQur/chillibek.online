"""Reproducible synthetic corpus metrics and local WSGI latency, never a live scan.

Run from repository root: python -m waf.scripts.security_report
Optional: --junit waf/local/security-tests.xml
"""
import argparse
import json
import platform
import statistics
import tempfile
import time
from defusedxml import ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, jsonify
from werkzeug.test import Client
from werkzeug.wrappers import Response

from waf.config import WAFSettings
from waf.policy import Policy
from waf.rules import inspect_values
from waf.wsgi import protect_wsgi


def distribution(samples):
    ordered = sorted(samples)
    return {'samples':len(samples), 'mean_ms':round(statistics.mean(samples), 4),
            'median_ms':round(statistics.median(samples), 4), 'p95_ms':round(ordered[int((len(ordered)-1)*0.95)], 4)}


def measure(client, count=40):
    for _ in range(5):
        if client.get('/api/menu', buffered=True).status_code != 200:
            raise RuntimeError('Synthetic benchmark warmup failed.')
    samples = []
    for _ in range(count):
        started = time.perf_counter()
        if client.get('/api/menu', buffered=True).status_code != 200:
            raise RuntimeError('Synthetic benchmark request failed.')
        samples.append((time.perf_counter() - started)*1000)
    return distribution(samples)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--junit', type=Path)
    parser.add_argument('--output', type=Path, default=Path('security/reports/security-results.json'))
    args = parser.parse_args()
    corpus = json.loads(Path('waf/tests/security_corpus.json').read_text(encoding='utf-8'))
    counts = dict(true_positives=0, false_positives=0, true_negatives=0, false_negatives=0)
    samples = []
    for case in corpus:
        started = time.perf_counter()
        detected = bool(inspect_values([case['value']], {case['category']})[0])
        samples.append((time.perf_counter() - started)*1000)
        key = ('true_positives' if detected else 'false_negatives') if case['malicious'] else ('false_positives' if detected else 'true_negatives')
        counts[key] += 1
    positive = counts['true_positives'] + counts['false_negatives']
    negative = counts['true_negatives'] + counts['false_positives']
    report = {'generated_at':datetime.now(timezone.utc).isoformat(), 'python':platform.python_version(),
        'scope':'Local synthetic corpus and single-process WSGI benchmark; not production effectiveness or capacity.',
        'corpus':{'cases':len(corpus), **counts, 'detection_rate_pct':round(100*counts['true_positives']/positive,2),
                  'false_positive_rate_pct':round(100*counts['false_positives']/negative,2)},
        'detector_latency':distribution(samples)}
    with tempfile.TemporaryDirectory(prefix='chillibek-security-metrics-') as directory:
        # Intentionally harmless private callable, no public test endpoints/server.
        restaurant = Flask('synthetic-benchmark')
        restaurant.add_url_rule('/api/menu', view_func=lambda:jsonify([{'id':1,'name':'Synthetic soup','price':1000}]))
        raw = measure(Client(restaurant, Response))
        wrapper = protect_wsgi(restaurant, WAFSettings(log_path=Path(directory)/'events.log', rate_limit_requests=10000,
                                                      route_limit_requests=10000))
        protected = measure(Client(wrapper, Response))
        store = wrapper.waf.state.policy_store
        before = store.read()
        disabled = Policy(**{name:('monitor' if name == 'mode' else False) for name in Policy.model_fields})
        store.update(disabled, before['revision'], 'synthetic-benchmark')
        minimal = measure(Client(wrapper, Response))
        wrapper.close()
        report['wsgi_latency'] = {'raw_flask':raw, 'all_modules_on':protected,
            'optional_modules_off':minimal, 'on_over_raw_mean_ms':round(protected['mean_ms']-raw['mean_ms'],4),
            'on_over_raw_pct':round(100*(protected['mean_ms']/raw['mean_ms']-1),2)}
    if args.junit:
        root = ET.parse(args.junit).getroot()
        report['python_tests'] = {key:sum(int(suite.attrib.get(key,0)) for suite in root.iter('testsuite'))
                                  for key in ['tests','failures','errors','skipped']}
    report['tools'] = {}
    for name in ['bandit', 'pip-audit']:
        path = Path('waf/local')/(name+'.json')
        if not path.exists():
            report['tools'][name] = {'status':'not run'}
        else:
            data = json.loads(path.read_text(encoding='utf-8'))
            if name == 'bandit':
                report['tools'][name] = {'findings':[{'id':item['test_id'],'severity':item['issue_severity'],
                    'file':item['filename'].replace('\\','/'),'line':item['line_number']} for item in data['results']], 'scan_errors':data['errors']}
            else:
                report['tools'][name] = {'packages':len(data['dependencies']), 'advisory_records':sum(len(item['vulns']) for item in data['dependencies']),
                    'skipped':[{'name':item['name'],'reason':item['skip_reason']} for item in data['dependencies'] if 'skip_reason' in item]}
    report['tools']['unavailable'] = ['Semgrep CE (not installed)', 'Trivy (not installed)', 'OWASP ZAP (not installed)', 'Docker (not installed)']
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2)+'\n', encoding='utf-8')
    print(json.dumps(report, indent=2))
    if counts['false_positives'] or counts['false_negatives']:
        raise SystemExit('Corpus regression: metrics recorded, verification failed.')


if __name__ == '__main__':
    main()
