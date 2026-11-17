import json
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import traceguard as tg


class DetectionTests(unittest.TestCase):
    def events(self, count=10, spacing=1, kind='auth_failure', users=False):
        base = datetime(2026, 1, 1, tzinfo=timezone.utc)
        rows = []
        for i in range(count):
            row = dict(timestamp=(base + timedelta(seconds=i * spacing)).isoformat(),
                       event_type=kind, host='test-host', src_ip='192.0.2.1',
                       user=f'user-{i}' if users else 'alice')
            if kind == 'network_connection':
                row['dst_port'] = 1000 + i
            rows.append(row)
        return tg.parse_events('\n'.join(json.dumps(row) for row in rows))

    def test_demo_has_all_four_rules(self):
        alerts = tg.detect(tg.parse_events(tg.demo_events()))
        self.assertEqual({a['rule'] for a in alerts}, set(tg.RULES))
        self.assertEqual(len(alerts), 4)

    def test_failure_threshold_and_window(self):
        self.assertEqual(tg.detect(self.events(9)), [])
        self.assertEqual(len(tg.detect(self.events(10))), 1)
        self.assertEqual(tg.detect(self.events(10, spacing=34)), [])

    def test_spray_requires_distinct_users(self):
        self.assertNotIn('TG-002', [a['rule'] for a in tg.detect(self.events(12))])
        self.assertEqual([a['rule'] for a in tg.detect(self.events(10, users=True))], ['TG-002'])

    def test_port_probe_threshold(self):
        self.assertEqual(tg.detect(self.events(19, kind='network_connection')), [])
        self.assertEqual(tg.detect(self.events(20, kind='network_connection'))[0]['rule'], 'TG-004')

    def test_sort_and_duplicate_stability(self):
        events = self.events()
        self.assertEqual(tg.detect(events), tg.detect(list(reversed(events)) + events))

    def test_inclusive_window_boundary(self):
        rows = self.events(9)
        last = dict(rows[-1], timestamp='2026-01-01T00:05:00+00:00')
        last.pop('id')
        boundary = tg.parse_events(json.dumps(last))
        self.assertEqual(len(tg.detect(rows + boundary)), 1)
        last['timestamp'] = '2026-01-01T00:05:01+00:00'
        self.assertEqual(tg.detect(rows + tg.parse_events(json.dumps(last))), [])

    def test_success_needs_matching_identity_and_resets_failures(self):
        rows = self.events(5)
        def success(user, seconds):
            return tg.parse_events(json.dumps(dict(timestamp=f'2026-01-01T00:00:{seconds:02d}Z', event_type='auth_success', host='test-host', src_ip='192.0.2.1', user=user)))[0]
        self.assertEqual(tg.detect(rows + [success('bob', 10)]), [])
        alerts = tg.detect(rows + [success('alice', 10), success('alice', 20)])
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]['rule'], 'TG-003')
        self.assertEqual(alerts[0]['evidence_total'], 6)

    def test_host_groups_are_isolated(self):
        rows = self.events(9)
        other = dict(rows[-1], host='other-host', timestamp='2026-01-01T00:00:10Z')
        other.pop('id')
        self.assertEqual(tg.detect(rows + tg.parse_events(json.dumps(other))), [])

    def test_network_ports_are_distinct(self):
        rows = self.events(25, kind='network_connection')
        for row in rows:
            row['dst_port'] = 443
        normalized = tg.parse_events('\n'.join(json.dumps(r) for r in rows))
        self.assertEqual(tg.detect(normalized), [])

    def test_ip_and_port_validation(self):
        row = dict(timestamp='2026-01-01T00:00:00Z', event_type='network_connection', host='h', src_ip='192.0.2.1', dst_port=443)
        for changes in [dict(src_ip='invalid'), dict(dst_port=True), dict(dst_port=65536), dict(dst_port='443')]:
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                tg.parse_events(json.dumps(dict(row, **changes)))

    def test_reject_bad_input(self):
        for raw in ['{}', 'not json', '', json.dumps(dict(timestamp='2026-01-01T00:00:00', event_type='auth_failure', host='x', src_ip='192.0.2.1', user='x'))]:
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                tg.parse_events(raw)


class WorkspaceTests(unittest.TestCase):
    def test_import_is_idempotent_and_case_persists(self):
        with tempfile.TemporaryDirectory() as directory:
            db = Path(directory) / 'test.db'
            events = tg.parse_events(tg.demo_events())
            self.assertEqual(tg.ingest(db, events), len(events))
            self.assertEqual(tg.ingest(db, events), 0)
            alert = tg.state(db)['alerts'][0]
            tg.update_case(db, alert['id'], 'Investigating', 'Review with identity team')
            self.assertEqual(tg.state(db)['alerts'][0]['status'], 'Investigating')
            self.assertEqual(tg.state(db)['alerts'][0]['notes'], 'Review with identity team')

    def test_html_does_not_embed_literal_script_in_notes(self):
        with tempfile.TemporaryDirectory() as directory:
            db = Path(directory) / 'test.db'
            tg.ingest(db, tg.parse_events(tg.demo_events()))
            alert = tg.state(db)['alerts'][0]
            payload = '</script><script>alert(1)</script>'
            tg.update_case(db, alert['id'], 'Investigating', payload)
            tg.report(db, Path(directory) / 'report')
            report = (Path(directory) / 'report' / 'report.html').read_text(encoding='utf-8')
            self.assertNotIn(payload, report)
            self.assertIn('\\u003c/script', report)

    def test_unknown_case_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                tg.update_case(Path(directory) / 'test.db', 'missing', 'Investigating', '')

    def test_demo_provenance_is_explicit(self):
        with tempfile.TemporaryDirectory() as directory:
            db = Path(directory) / 'test.db'
            events = tg.parse_events(tg.demo_events())
            tg.ingest(db, events, synthetic=True)
            self.assertTrue(tg.state(db)['synthetic'])
            tg.ingest(db, events)
            self.assertFalse(tg.state(db)['synthetic'])

    def test_cli_demo_and_repeated_demo_rejection(self):
        with tempfile.TemporaryDirectory() as directory:
            args = ['--db', str(Path(directory) / 'test.db'), 'demo', '--output', str(Path(directory) / 'out')]
            self.assertEqual(tg.main(args), 0)
            self.assertTrue((Path(directory) / 'out' / 'report.json').is_file())
            self.assertEqual(tg.main(args), 1)


if __name__ == '__main__':
    unittest.main()
