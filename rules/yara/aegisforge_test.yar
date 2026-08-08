rule aegisforge_test_marker
{
    strings:
        $marker = "AEGISFORGE_TEST_SIGNATURE"

    condition:
        $marker
}