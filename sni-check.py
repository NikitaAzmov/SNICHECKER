#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sni-check.py — подбор лучшего dest/SNI для VLESS Reality.

Запускать НА НОДЕ (там, где крутится Xray) — латентность меряется с сервера.
Только стандартная библиотека Python 3 — ничего ставить не нужно.

Проверяет для каждого домена:
  • PING   — время TCP-коннекта (мс)
  • TLS1.3 — поддержка TLS 1.3
  • H2     — ALPN h2 (HTTP/2)
  • CURVE  — группа обмена ключами (для Reality нужен X25519)
  • CERT   — валидность сертификата
  • CDN    — детект Cloudflare/Akamai (нежелательны)
В конце — таблица, отсортированная по пингу, и однозначный ЛУЧШИЙ выбор
с готовыми строками для конфига.

Использование:
  python3 sni-check.py                          # встроенный список кандидатов
  python3 sni-check.py images.apple.com max.ru  # свои домены
  python3 sni-check.py --csv reality_sni.csv    # домены из вывода RealiTLScanner
  python3 sni-check.py --port 443 --timeout 6
"""

import argparse
import concurrent.futures as cf
import socket
import ssl
import subprocess
import sys
import time

# --- встроенный список стабильных кандидатов под Reality (лето 2026) ---
DEFAULT_DOMAINS = [
    "images.apple.com",
    "www.apple.com",
    "gateway.icloud.com",
    "www.yahoo.com",
    "dl.google.com",
    "www.nvidia.com",
    "www.swift.com",
    "fallback.cdn-tinkoff.ru",
    "userapi.com",
    "max.ru",
    "aws.amazon.com",
    "www.amd.com",
]

# ---- цвета ----
class C:
    R = "\033[31m"; G = "\033[32m"; Y = "\033[33m"; B = "\033[36m"
    GR = "\033[90m"; BOLD = "\033[1m"; RST = "\033[0m"

def col(s, c):
    return f"{c}{s}{C.RST}"

def vlen(s):
    """видимая длина строки без ANSI-кодов"""
    out, i = 0, 0
    while i < len(s):
        if s[i] == "\033":
            while i < len(s) and s[i] != "m":
                i += 1
        else:
            out += 1
        i += 1
    return out

def pad(s, w):
    return s + " " * max(0, w - vlen(s))


def tcp_ping(host, port, timeout):
    """минимальное время TCP-коннекта из 3 попыток, мс; None если недоступен"""
    best = None
    for _ in range(3):
        try:
            t0 = time.perf_counter()
            with socket.create_connection((host, port), timeout=timeout):
                dt = (time.perf_counter() - t0) * 1000.0
            best = dt if best is None else min(best, dt)
        except Exception:
            pass
    return best


def get_curve(host, port, timeout):
    """группа обмена ключами через openssl (если есть); иначе '?'"""
    try:
        p = subprocess.run(
            ["openssl", "s_client", "-connect", f"{host}:{port}",
             "-servername", host, "-tls1_3"],
            input=b"", capture_output=True, timeout=timeout + 3,
        )
        out = (p.stdout + p.stderr).decode("utf-8", "ignore")
        for line in out.splitlines():
            if "Server Temp Key:" in line:
                # пример: "Server Temp Key: X25519, 253 bits"
                return line.split(":", 1)[1].strip().split(",")[0].strip()
    except Exception:
        pass
    return "?"


def check(host, port, timeout):
    r = {
        "host": host, "ping": None, "tls13": False, "h2": False,
        "curve": "?", "cert_ok": False, "cn": "", "issuer": "",
        "cdn": "-", "error": "",
    }

    r["ping"] = tcp_ping(host, port, timeout)
    if r["ping"] is None:
        r["error"] = "нет TCP-коннекта"
        return r

    # --- TLS 1.3 + ALPN h2 + валидация серта ---
    ctx = ssl.create_default_context()
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    except Exception:
        pass
    try:
        ctx.set_alpn_protocols(["h2", "http/1.1"])
    except Exception:
        pass

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                r["tls13"] = (ss.version() == "TLSv1.3")
                r["h2"] = (ss.selected_alpn_protocol() == "h2")
                r["cert_ok"] = True  # дошли сюда -> серт прошёл валидацию
                cert = ss.getpeercert() or {}
                for t in cert.get("subject", ()):
                    for k, v in t:
                        if k == "commonName":
                            r["cn"] = v
                for t in cert.get("issuer", ()):
                    for k, v in t:
                        if k == "organizationName":
                            r["issuer"] = v
    except ssl.SSLError:
        r["error"] = "TLS1.3/cert fail"
    except Exception as e:
        r["error"] = type(e).__name__

    # детект CDN по CN/issuer
    blob = f"{r['cn']} {r['issuer']}".lower()
    if "cloudflare" in blob:
        r["cdn"] = "Cloudflare"
    elif "akamai" in blob:
        r["cdn"] = "Akamai"

    r["curve"] = get_curve(host, port, timeout)
    return r


def verdict(r):
    if r["error"] and not (r["tls13"] and r["h2"]):
        return col("✗ не годится", C.R), 0
    if not (r["tls13"] and r["h2"] and r["cert_ok"]):
        return col("✗ не годится", C.R), 0
    if r["cdn"] == "Cloudflare":
        return col("⚠ Cloudflare", C.Y), 1
    if r["cdn"] == "Akamai":
        return col("⚠ Akamai", C.Y), 1
    if "X25519" not in r["curve"] and r["curve"] != "?":
        return col("⚠ нет X25519", C.Y), 1
    return col("✓ подходит", C.G), 2


def load_csv(path):
    """достаём CERT_DOMAIN из вывода RealiTLScanner; пропускаем wildcard/мусор"""
    doms = []
    try:
        with open(path, encoding="utf-8") as f:
            head = f.readline().strip().split(",")
            try:
                idx = head.index("CERT_DOMAIN")
            except ValueError:
                idx = 8
            for line in f:
                parts = line.rstrip("\n").split(",")
                if len(parts) <= idx:
                    continue
                d = parts[idx].strip().strip('"')
                if not d or d.startswith("*") or " " in d:
                    continue
                if d not in doms:
                    doms.append(d)
    except Exception as e:
        print(f"{C.R}не смог прочитать CSV {path}: {e}{C.RST}", file=sys.stderr)
    return doms


def main():
    ap = argparse.ArgumentParser(add_help=True)
    ap.add_argument("domains", nargs="*", help="домены для проверки")
    ap.add_argument("--csv", help="файл вывода RealiTLScanner (reality_sni.csv)")
    ap.add_argument("--port", type=int, default=443)
    ap.add_argument("--timeout", type=int, default=6)
    args = ap.parse_args()

    domains = list(args.domains)
    if args.csv:
        domains += load_csv(args.csv)
    if not domains:
        domains = list(DEFAULT_DOMAINS)
    # дедуп с сохранением порядка
    seen, uniq = set(), []
    for d in domains:
        if d not in seen:
            seen.add(d); uniq.append(d)
    domains = uniq

    print(f"\n{C.BOLD}Проверяю {len(domains)} доменов "
          f"(порт {args.port}, таймаут {args.timeout}s)...{C.RST}\n")

    results = []
    with cf.ThreadPoolExecutor(max_workers=16) as ex:
        futs = {ex.submit(check, d, args.port, args.timeout): d for d in domains}
        for fu in cf.as_completed(futs):
            results.append(fu.result())

    # ранжируем: сначала по score (подходит>warn>нет), потом по пингу
    def keyf(r):
        _, sc = verdict(r)
        ping = r["ping"] if r["ping"] is not None else 9e9
        return (-sc, ping)
    results.sort(key=keyf)

    # ---- таблица ----
    cols = [("DOMAIN", 26), ("PING", 9), ("TLS1.3", 7), ("H2", 4),
            ("CURVE", 16), ("CERT", 5), ("CDN", 11), ("VERDICT", 14)]
    header = "".join(pad(col(n, C.BOLD), w) for n, w in cols)
    print(header)
    print(col("─" * (sum(w for _, w in cols)), C.GR))

    def yn(b):
        return col("OK", C.G) if b else col("NO", C.R)

    for r in results:
        v, _ = verdict(r)
        ping = f"{r['ping']:.0f}ms" if r["ping"] is not None else col("—", C.GR)
        curve = r["curve"]
        if "X25519" in curve:
            curve = col(curve, C.G)
        elif curve == "?":
            curve = col("?", C.GR)
        cdn = r["cdn"]
        if cdn in ("Cloudflare", "Akamai"):
            cdn = col(cdn, C.Y)
        row = [
            (col(r["host"], C.B), 26),
            (ping, 9),
            (yn(r["tls13"]), 7),
            (yn(r["h2"]), 4),
            (curve, 16),
            (yn(r["cert_ok"]), 5),
            (cdn, 11),
            (v, 14),
        ]
        print("".join(pad(s, w) for s, w in row))

    # ---- лучший ----
    best = None
    for r in results:
        _, sc = verdict(r)
        if sc == 2:  # полностью подходит
            best = r
            break

    print()
    if best:
        print(col("━" * 60, C.G))
        print(f"{C.BOLD}{C.G}🏆 ЛУЧШИЙ ВЫБОР: {best['host']}{C.RST}  "
              f"({best['ping']:.0f}ms, {best['curve']})")
        print(col("━" * 60, C.G))
        print(f"\n{C.BOLD}Вставьте в realitySettings:{C.RST}\n")
        print(f'  "dest": "{best["host"]}:443",')
        print(f'  "serverNames": ["{best["host"]}"],')
        print(f"\n{C.Y}⚠ В remnawave SNI в настройках Host тоже поменяйте "
              f"на {best['host']}{C.RST}\n")
    else:
        print(col("Не нашлось идеального кандидата (все с ⚠ или ✗). "
                  "Возьмите лучший '⚠' с низким пингом и без CDN.", C.Y))
        print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
