#!/usr/bin/env python3
"""Helper SSH vào cluster lab bằng paramiko (mọi node đều user dat, password 1).

Cách dùng:
  python3 scripts/ssh_lab.py COMMAND               # mặc định host=10.1.16.234
  python3 scripts/ssh_lab.py --host HOST COMMAND   # host chỉ định
  python3 scripts/ssh_lab.py --list               # liệt kê 6 node + kiểm tra kết nối

CHỈ dùng trong môi trường lab tin cậy nơi mật khẩu yếu được chủ sở hữu cung cấp.
"""
import sys
import paramiko

HOSTS = {
    "10.1.16.234": "k8s-master.local",
    "10.1.16.235": "k8s-master2.local",
    "10.1.16.236": "k8s-master3.local",
    "10.1.16.237": "k8s-worker1.local",
    "10.1.16.238": "k8s-worker4.local",
    "10.1.16.239": "k8s-worker3.local",
}
USER = "dat"
PASSWORD = "1"
PORT = 22
TIMEOUT = 30


def run(host, cmd, timeout=TIMEOUT * 10):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            host,
            port=PORT,
            username=USER,
            password=PASSWORD,
            timeout=TIMEOUT,
            look_for_keys=False,
            allow_agent=False,
        )
    except Exception as exc:  # noqa: BLE001
        print(f"SSH connect failed to {host}: {exc}", file=sys.stderr)
        return 2, ""
    stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode("utf-8", "replace")
    err = stderr.read().decode("utf-8", "replace")
    code = stdout.channel.recv_exit_status()
    if out:
        print(out)
    if err:
        print(f"STDERR({host}): {err}", file=sys.stderr)
    client.close()
    return code, out


def main():
    args = sys.argv[1:]
    if args and args[0] == "--list":
        for host, name in HOSTS.items():
            code, out = run(host, "hostname; echo ok")
            status = "OK" if code == 0 else "FAIL"
            print(f"{name} ({host}): {status}")
        return 0
    host = "10.1.16.234"
    if args and args[0] in HOSTS:
        host = args.pop(0)
    cmd = " ".join(args) or "hostname; whoami; pwd; uname -a"
    code, _ = run(host, cmd)
    return code


if __name__ == "__main__":
    sys.exit(main())