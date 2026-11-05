"""Real instruction fixtures for the Windows Testing Dev and Canary builds."""
import mv2ctl as ctl
import test_win_beta_profile as profiles


class WindowsTestingCanaryProfileTests(profiles.WindowsBetaProfileTests):
    fixture_name = 'chrome-testing-canary-159.0.8141.0-win64.json'
    install_offset = 0xc00
    install_kind = 'W5_159_8141'
    startup_pattern = ctl.WIN_STARTUP_V11


class WindowsTestingDevProfileTests(profiles.WindowsBetaProfileTests):
    fixture_name = 'chrome-testing-dev-159.0.8130.0-win64.json'
    install_offset = 0xc00
    install_kind = 'W5_159'
    startup_pattern = ctl.WIN_STARTUP_V13
