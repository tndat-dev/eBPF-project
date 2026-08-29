#!/usr/bin/env python3
"""Helper SSH vào cluster lab bằng paramiko (mọi node đều user dat, password 1).

Cách dùng:
  python3 scripts/ssh_lab.py COMMAND               # mặc định host=10.1.16.234
  python3 scripts/ssh_lab.py --host HOST COMMAND   # host chỉ định
  python3 scripts/ssh_lab.py --list               # liệt kê 6 node + kiểm tra kết nối

CHỈ dùng trong môi trường lab tin cậy nơi mật khẩu yếu được chủ sở hữu cung cấp.
"""
import argparse
import os
import shlex
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
USER = os.environ.get("LAB_SSH_USER", "dat")
PASSWORD = os.environ.get("LAB_SSH_PASSWORD")
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
            look_for_keys=PASSWORD is None,
            allow_agent=PASSWORD is None,
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
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", choices=tuple(HOSTS), default="10.1.16.234")
    parser.add_argument("--list", action="store_true")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.list:
        for host, name in HOSTS.items():
            code, out = run(host, "hostname; echo ok")
            status = "OK" if code == 0 else "FAIL"
            print(f"{name} ({host}): {status}")
        return 0
    command = shlex.join(args.command) if args.command else "hostname; whoami; pwd; uname -a"
    code, _ = run(args.host, command)
    return code


if __name__ == "__main__":
    sys.exit(main())
