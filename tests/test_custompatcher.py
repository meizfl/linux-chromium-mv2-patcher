import contextlib
import io
import json
import unittest
from unittest.mock import Mock

import custompatcher as c


class CustomPatcherTests(unittest.TestCase):
    def backend(self, state='original'):
        backend = Mock()
        backend.analyze.return_value = ([], state, None)
        return backend

    def run_cli(self, argv, backend):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            c.main(argv, backend)
        return out.getvalue()

    def test_default_request_refuses_all_writes_even_with_valid_mv2(self):
        backend = self.backend()
        with self.assertRaisesRegex(SystemExit, 'google-sync, sync-url, gaia-url, password-manager'):
            self.run_cli(['apply', '/tmp/browser', '--yes'], backend)
        backend.cmd_apply.assert_not_called()
        backend.cmd_test_apply.assert_not_called()

    def test_unknown_and_partial_builds_cannot_be_trial_patched(self):
        for state in ('fail', 'mixed'):
            with self.subTest(state=state):
                backend = self.backend(state)
                with self.assertRaisesRegex(SystemExit, 'Nothing was written'):
                    self.run_cli(['test-apply', '/tmp/browser', '--features', 'mv2'], backend)
                backend.cmd_test_apply.assert_not_called()

    def test_mv2_dispatch_uses_verified_backend(self):
        backend = self.backend()
        self.run_cli(['test-apply', '/tmp/browser', '--features', 'mv2',
                      '--output', '/tmp/copy'], backend)
        backend.cmd_test_apply.assert_called_once_with('/tmp/browser', '/tmp/copy')
        self.run_cli(['apply', '/tmp/browser', '--features', 'mv2', '--yes'], backend)
        backend.cmd_apply.assert_called_once_with('/tmp/browser', True)

    def test_already_patched_is_noop(self):
        backend = self.backend('patched')
        self.run_cli(['apply', '/tmp/browser', '--features', 'mv2'], backend)
        backend.cmd_apply.assert_not_called()

    def test_json_does_not_claim_runtime_feature_availability(self):
        backend = self.backend()
        report = json.loads(self.run_cli(['analyze', '/tmp/browser', '--json'], backend))
        self.assertEqual(report['features']['google-sync']['state'], 'unsupported')
        self.assertEqual(report['features']['password-manager']['state'], 'unsupported')
        self.assertEqual(report['features']['mv2']['state'], 'original')

    def test_invalid_options_fail_before_inspection(self):
        for options in (['--json'], ['--output', '/tmp/copy']):
            backend = self.backend()
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                self.run_cli(['apply', '/tmp/browser', *options], backend)
            backend.analyze.assert_not_called()


if __name__ == '__main__':
    unittest.main()
