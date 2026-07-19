"""Unit tests for the pure helpers in secops_toolkit_mcp.core."""

import pytest

from secops_toolkit_mcp import core


# --- extract_iocs ---------------------------------------------------------


def test_extract_iocs_finds_each_type():
    text = (
        "Attacker 203.0.113.7 hosted http://evil.example.com/payload, "
        "dropped a file with sha256 "
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 "
        "and referenced CVE-2021-44228."
    )
    iocs = core.extract_iocs(text)
    assert iocs["ipv4"] == ["203.0.113.7"]
    assert "http://evil.example.com/payload" in iocs["url"]
    assert "evil.example.com" in iocs["domain"]
    assert iocs["sha256"] == [
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    ]
    assert iocs["cve"] == ["CVE-2021-44228"]


def test_extract_iocs_handles_defanged_input():
    iocs = core.extract_iocs("beacon to 1.2.3[.]4 via hxxp://bad[.]example[.]org")
    assert "1.2.3.4" in iocs["ipv4"]
    assert "http://bad.example.org" in iocs["url"]


def test_extract_iocs_deduplicates_and_sorts():
    iocs = core.extract_iocs("10.0.0.1 then 10.0.0.1 then 10.0.0.2")
    assert iocs["ipv4"] == ["10.0.0.1", "10.0.0.2"]


def test_extract_iocs_empty_text_returns_empty_dict():
    assert core.extract_iocs("nothing to see here") == {}


def test_extract_iocs_does_not_treat_ip_as_domain():
    iocs = core.extract_iocs("just an ip 8.8.8.8")
    assert iocs.get("ipv4") == ["8.8.8.8"]
    assert "domain" not in iocs


# --- defang / refang ------------------------------------------------------


def test_defang_then_refang_roundtrips_a_url():
    original = "http://malware.example.com/a.exe"
    defanged = core.defang_ioc(original)
    # defang neutralises every dot, including the one in the filename.
    assert defanged == "hxxp[://]malware[.]example[.]com/a[.]exe"
    # refang must fully reverse it.
    assert core.refang_ioc(defanged) == original


def test_refang_accepts_paren_dot_variant():
    assert core.refang_ioc("evil(.)com") == "evil.com"


# --- hash_text ------------------------------------------------------------


def test_hash_text_known_sha256_of_empty_string():
    result = core.hash_text("", "sha256")
    assert result["algorithm"] == "sha256"
    assert result["hex_digest"] == (
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )


def test_hash_text_defaults_to_sha256():
    assert core.hash_text("hello")["algorithm"] == "sha256"


def test_hash_text_rejects_unknown_algorithm():
    with pytest.raises(ValueError, match="unsupported algorithm"):
        core.hash_text("hello", "crc32")


# --- password_entropy -----------------------------------------------------


def test_password_entropy_empty():
    result = core.password_entropy("")
    assert result["strength"] == "empty"
    assert result["entropy_bits"] == 0.0


def test_password_entropy_charset_grows_with_variety():
    weak = core.password_entropy("aaaa")           # lowercase only -> pool 26
    strong = core.password_entropy("aA1!aA1!")     # all four classes -> pool 94
    assert weak["charset_size"] == 26
    assert strong["charset_size"] == 94
    assert strong["entropy_bits"] > weak["entropy_bits"]


def test_password_entropy_strength_label_for_long_complex():
    result = core.password_entropy("Tr0ub4dour&3xtra-Long-Passphrase!")
    assert result["strength"] in {"strong", "very strong"}


# --- cidr_info ------------------------------------------------------------


def test_cidr_info_ipv4_basics():
    info = core.cidr_info("192.168.1.0/24")
    assert info["prefix_length"] == 24
    assert info["num_addresses"] == 256
    assert info["first_host"] == "192.168.1.1"
    assert info["last_host"] == "192.168.1.254"
    assert info["broadcast"] == "192.168.1.255"
    assert info["is_private"] is True


def test_cidr_info_accepts_host_bits_set():
    # strict=False means a host address with a prefix is accepted.
    info = core.cidr_info("10.0.0.5/8")
    assert info["network"] == "10.0.0.0"


def test_cidr_info_rejects_garbage():
    with pytest.raises(ValueError, match="invalid CIDR"):
        core.cidr_info("not-a-network")


# --- ip_in_cidr -----------------------------------------------------------


def test_ip_in_cidr_true_and_false():
    assert core.ip_in_cidr("192.168.1.50", "192.168.1.0/24") is True
    assert core.ip_in_cidr("192.168.2.50", "192.168.1.0/24") is False


def test_ip_in_cidr_rejects_bad_ip():
    with pytest.raises(ValueError, match="invalid IP address"):
        core.ip_in_cidr("999.999.999.999", "192.168.1.0/24")


# --- scan_repo_root ---------------------------------------------------------


def test_scan_repo_root_clean_directory(tmp_path):
    (tmp_path / "README.md").write_text("hello")
    (tmp_path / "main.py").write_text("print('hi')")
    result = core.scan_repo_root(str(tmp_path))
    assert result["clean"] is True
    assert result["findings"] == []
    assert result["entries_scanned"] == 2


def test_scan_repo_root_flags_git_exe_as_critical(tmp_path):
    (tmp_path / "git.exe").write_bytes(b"MZ")
    result = core.scan_repo_root(str(tmp_path))
    assert result["clean"] is False
    assert result["findings"] == [
        {"filename": "git.exe", "shadows": "git", "severity": "critical"}
    ]


def test_scan_repo_root_is_case_insensitive(tmp_path):
    (tmp_path / "GIT.EXE").write_bytes(b"MZ")
    result = core.scan_repo_root(str(tmp_path))
    assert result["findings"][0]["shadows"] == "git"
    assert result["findings"][0]["severity"] == "critical"


def test_scan_repo_root_flags_shell_and_tool_names_by_tier(tmp_path):
    (tmp_path / "node.cmd").write_bytes(b"")
    (tmp_path / "docker.bat").write_bytes(b"")
    result = core.scan_repo_root(str(tmp_path))
    by_name = {f["filename"]: f["severity"] for f in result["findings"]}
    assert by_name["node.cmd"] == "high"
    assert by_name["docker.bat"] == "medium"


def test_scan_repo_root_ignores_non_executable_extension(tmp_path):
    (tmp_path / "git.txt").write_text("not an exe")
    result = core.scan_repo_root(str(tmp_path))
    assert result["clean"] is True


def test_scan_repo_root_ignores_unrelated_executable_name(tmp_path):
    (tmp_path / "setup.exe").write_bytes(b"MZ")
    result = core.scan_repo_root(str(tmp_path))
    assert result["clean"] is True


def test_scan_repo_root_only_checks_top_level(tmp_path):
    nested = tmp_path / "vendor"
    nested.mkdir()
    (nested / "git.exe").write_bytes(b"MZ")
    result = core.scan_repo_root(str(tmp_path))
    assert result["clean"] is True
    assert result["entries_scanned"] == 0


def test_scan_repo_root_rejects_missing_path(tmp_path):
    with pytest.raises(ValueError, match="path does not exist"):
        core.scan_repo_root(str(tmp_path / "does-not-exist"))


def test_scan_repo_root_rejects_a_file_path(tmp_path):
    f = tmp_path / "not_a_dir.txt"
    f.write_text("x")
    with pytest.raises(ValueError, match="not a directory"):
        core.scan_repo_root(str(f))
