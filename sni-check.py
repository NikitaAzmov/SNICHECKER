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
import urllib.request

# --- ГЛОБАЛЬНЫЕ бренды (нейтральны к гео, проверяются всегда) ---
GLOBAL_DOMAINS = [
    # Apple
    "www.apple.com", "images.apple.com", "gateway.icloud.com", "www.icloud.com",
    "support.apple.com", "swcdn.apple.com",
    # Microsoft
    "www.microsoft.com", "www.bing.com", "www.office.com", "www.xbox.com",
    "www.msn.com", "www.skype.com", "www.visualstudio.com",
    # Google
    "dl.google.com", "www.google.com", "www.youtube.com", "storage.googleapis.com",
    "www.gstatic.com", "fonts.googleapis.com",
    # Amazon
    "aws.amazon.com", "www.amazon.com", "m.media-amazon.com",
    # Yahoo
    "www.yahoo.com",
    # железо
    "www.nvidia.com", "www.amd.com", "www.intel.com", "www.qualcomm.com",
    "www.dell.com", "www.hp.com", "www.lenovo.com", "www.asus.com",
    "www.tesla.com", "www.samsung.com", "www.lg.com",
    # финансы
    "www.swift.com", "www.visa.com", "www.mastercard.com", "www.paypal.com",
    "www.americanexpress.com", "www.jpmorgan.com",
    # технологии / медиа
    "www.netflix.com", "www.spotify.com", "www.linkedin.com", "www.tiktok.com",
    "www.adobe.com", "www.oracle.com", "www.ibm.com", "www.cisco.com",
    "www.salesforce.com", "www.sap.com", "www.dropbox.com", "www.atlassian.com",
    "www.gitlab.com", "www.python.org", "www.mozilla.org", "en.wikipedia.org",
    "www.reddit.com", "www.twitch.tv", "www.ebay.com", "www.booking.com",
    "www.airbnb.com", "www.pinterest.com", "zoom.us",
]

# --- ЛОКАЛЬНЫЕ домены по странам (код ISO -> список) ---
# Подбираются по флагу --country XX. Дают минимальный пинг для ноды в этой стране.
COUNTRY_DOMAINS = {
    "de": [  # Германия
        "www.bmw.de", "www.mercedes-benz.com", "www.volkswagen.de",
        "www.siemens.com", "www.bosch.com", "www.deutsche-bank.de",
        "www.commerzbank.de", "www.telekom.de", "www.spiegel.de",
        "www.bild.de", "www.zalando.de", "www.dhl.de", "www.lufthansa.com",
        "www.allianz.de", "www.sparkasse.de", "www.1und1.de",
    ],
    "fi": [  # Финляндия
        "www.nokia.com", "www.elisa.fi", "www.telia.fi", "www.op.fi",
        "www.nordea.fi", "www.yle.fi", "www.hs.fi", "www.kesko.fi",
        "www.finnair.com", "www.fortum.com", "www.s-pankki.fi",
    ],
    "us": [  # США
        "www.cnn.com", "www.nytimes.com", "www.walmart.com", "www.target.com",
        "www.bankofamerica.com", "www.wellsfargo.com", "www.chase.com",
        "www.att.com", "www.verizon.com", "www.comcast.com", "www.ford.com",
        "www.gm.com", "www.costco.com", "www.homedepot.com",
    ],
    "fr": [  # Франция
        "www.orange.fr", "www.sfr.fr", "www.free.fr", "www.bnpparibas",
        "www.societegenerale.fr", "www.creditagricole.fr", "www.lemonde.fr",
        "www.lefigaro.fr", "www.leboncoin.fr", "www.carrefour.fr",
        "www.sncf.com", "www.airfrance.fr", "www.loreal.com",
    ],
    "nl": [  # Нидерланды
        "www.ing.nl", "www.rabobank.nl", "www.abnamro.nl", "www.kpn.com",
        "www.bol.com", "www.nu.nl", "www.telegraaf.nl", "www.ah.nl",
        "www.klm.com", "www.philips.com", "www.asml.com",
    ],
    "se": [  # Швеция
        "www.ericsson.com", "www.telia.se", "www.tele2.se", "www.swedbank.se",
        "www.seb.se", "www.handelsbanken.se", "www.svt.se",
        "www.aftonbladet.se", "www.ikea.com", "www.volvocars.com", "www.hm.com",
    ],
    "gb": [  # Великобритания
        "www.bbc.co.uk", "www.theguardian.com", "www.hsbc.co.uk",
        "www.barclays.co.uk", "www.lloydsbank.com", "www.vodafone.co.uk",
        "www.bt.com", "www.tesco.com", "www.sky.com", "www.britishairways.com",
    ],
    "pl": [  # Польша
        "www.pkobp.pl", "www.onet.pl", "www.wp.pl", "www.allegro.pl",
        "www.orange.pl", "www.play.pl", "www.gazeta.pl", "www.interia.pl",
    ],
    "it": [  # Италия
        "www.tim.it", "www.vodafone.it", "www.unicredit.it",
        "www.intesasanpaolo.com", "www.repubblica.it", "www.corriere.it",
        "www.ferrari.com", "www.eni.com",
    ],
    "es": [  # Испания
        "www.telefonica.com", "www.movistar.es", "www.bbva.es",
        "www.santander.com", "www.elpais.com", "www.elmundo.es",
        "www.zara.com", "www.iberia.com",
    ],
    "no": [  # Норвегия
        "www.telenor.no", "www.dnb.no", "www.vg.no", "www.nrk.no",
        "www.equinor.com", "www.finn.no",
    ],
    "dk": [  # Дания
        "www.danskebank.dk", "www.tdc.dk", "www.dr.dk", "www.maersk.com",
        "www.novonordisk.com", "www.lego.com",
    ],
    "ch": [  # Швейцария
        "www.ubs.com", "www.swisscom.ch", "www.nestle.com", "www.roche.com",
        "www.novartis.com", "www.swiss.com",
    ],
    "at": [  # Австрия
        "www.a1.net", "www.erstebank.at", "www.orf.at", "www.derstandard.at",
        "www.redbull.com",
    ],
    "cz": [  # Чехия
        "www.seznam.cz", "www.cez.cz", "www.csob.cz", "www.idnes.cz",
    ],
    "be": [  # Бельгия
        "www.kbc.be", "www.proximus.be", "www.standaard.be", "www.delhaize.be",
    ],
    "ie": [  # Ирландия
        "www.aib.ie", "www.bankofireland.com", "www.rte.ie",
        "www.independent.ie",
    ],
    "pt": [  # Португалия
        "www.sapo.pt", "www.publico.pt", "www.cgd.pt", "www.continente.pt",
    ],
    "ro": [  # Румыния
        "www.emag.ro", "www.bnr.ro", "www.digi24.ro",
    ],
    "tr": [  # Турция
        "www.turkcell.com.tr", "www.garantibbva.com.tr", "www.hurriyet.com.tr",
        "www.trendyol.com",
    ],
    "ca": [  # Канада
        "www.rbc.com", "www.td.com", "www.bell.ca", "www.rogers.com",
        "www.cbc.ca", "www.shopify.com",
    ],
    "jp": [  # Япония
        "www.rakuten.co.jp", "www.nintendo.co.jp", "www.sony.co.jp",
        "www.nikkei.com", "www.softbank.jp", "www.docomo.ne.jp", "www.au.com",
        "line.me", "www.mufg.jp", "www.jal.co.jp", "www.ana.co.jp",
        "www.toyota.jp", "global.canon", "www.fujitsu.com", "www.ntt.com",
        "www.kddi.com",
    ],
    "ru": [  # Россия
        "ya.ru", "dzen.ru", "userapi.com", "vk.com", "ok.ru", "mail.ru",
        "max.ru", "avito.ru", "www.ozon.ru", "www.wildberries.ru",
        "www.tbank.ru", "fallback.cdn-tinkoff.ru", "www.gosuslugi.ru",
        "rutube.ru", "www.mts.ru", "www.megafon.ru", "2gis.ru", "hh.ru",
        "www.sber.ru",
    ],
}

# европейские страны для алиаса --country eu
EU_CODES = ["de", "fi", "fr", "nl", "se", "gb", "pl", "it", "es", "no",
            "dk", "ch", "at", "cz", "be", "ie", "pt", "ro"]

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


def server_ip():
    """внешний IP ноды; при неудаче — локальный IP; иначе 'неизвестно'"""
    for url in ("https://api.ipify.org", "http://api.ipify.org",
                "https://ifconfig.me/ip"):
        try:
            ip = urllib.request.urlopen(url, timeout=4).read().decode().strip()
            if ip and len(ip) <= 45:
                return ip
        except Exception:
            pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "неизвестно"


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
    ap.add_argument("--country", nargs="*", default=[],
                    help="коды стран (de fi us fr nl se ...), 'eu' = вся Европа, "
                         "'all' = все страны. Добавляет локальные домены к глобальным.")
    ap.add_argument("--list-countries", action="store_true",
                    help="показать доступные коды стран и выйти")
    ap.add_argument("--csv", help="файл вывода RealiTLScanner (reality_sni.csv)")
    ap.add_argument("--port", type=int, default=443)
    ap.add_argument("--timeout", type=int, default=6)
    ap.add_argument("--top", type=int, default=15,
                    help="сколько лучших доменов показать (0 = все)")
    args = ap.parse_args()

    if args.list_countries:
        print(f"\n{C.BOLD}Доступные коды стран:{C.RST}")
        for code in sorted(COUNTRY_DOMAINS):
            tag = col("EU", C.B) if code in EU_CODES else "  "
            print(f"  {code}  {tag}  ({len(COUNTRY_DOMAINS[code])} доменов)")
        print(f"\nАлиасы: {col('eu', C.G)} = вся Европа, "
              f"{col('all', C.G)} = все страны")
        print(f"Пример: {C.B}python3 sni.py --country de fi{C.RST}\n")
        return

    # разбираем коды стран (поддержка 'de,fi' и 'de fi')
    codes = []
    for part in args.country:
        for c in part.replace(",", " ").split():
            c = c.lower()
            if c == "eu":
                codes += EU_CODES
            elif c == "all":
                codes += list(COUNTRY_DOMAINS)
            else:
                codes.append(c)
    for c in codes:
        if c not in COUNTRY_DOMAINS:
            print(f"{C.Y}неизвестный код страны: {c} "
                  f"(см. --list-countries){C.RST}", file=sys.stderr)

    domains = list(args.domains)
    if args.csv:
        domains += load_csv(args.csv)
    if not domains:
        domains = list(GLOBAL_DOMAINS)
        for c in codes:
            domains += COUNTRY_DOMAINS.get(c, [])
    # дедуп с сохранением порядка
    seen, uniq = set(), []
    for d in domains:
        if d not in seen:
            seen.add(d); uniq.append(d)
    domains = uniq

    print(f"\n{C.BOLD}Проверяю {len(domains)} доменов "
          f"(порт {args.port}, таймаут {args.timeout}s)...{C.RST}\n")

    results = []
    done = 0
    with cf.ThreadPoolExecutor(max_workers=24) as ex:
        futs = {ex.submit(check, d, args.port, args.timeout): d for d in domains}
        for fu in cf.as_completed(futs):
            results.append(fu.result())
            done += 1
            print(f"\r  проверено {done}/{len(domains)}...", end="", flush=True)
    print("\r" + " " * 40 + "\r", end="")  # стираем прогресс

    # ранжируем: сначала по score (подходит>warn>нет), потом по пингу
    def keyf(r):
        _, sc = verdict(r)
        ping = r["ping"] if r["ping"] is not None else 9e9
        return (-sc, ping)
    results.sort(key=keyf)

    # ---- сводка ----
    good = sum(1 for r in results if verdict(r)[1] == 2)
    warn = sum(1 for r in results if verdict(r)[1] == 1)
    shown = results if args.top <= 0 else results[:args.top]
    print(f"{C.BOLD}Проверено: {len(results)}   "
          f"{C.G}✓ подходит: {good}{C.RST}   "
          f"{C.Y}⚠ с оговоркой: {warn}{C.RST}   "
          f"{C.GR}показаны топ-{len(shown)}{C.RST}\n")

    # ---- таблица ----
    cols = [("DOMAIN", 26), ("PING", 9), ("TLS1.3", 7), ("H2", 4),
            ("CURVE", 16), ("CERT", 5), ("CDN", 11), ("VERDICT", 14)]
    header = "".join(pad(col(n, C.BOLD), w) for n, w in cols)
    print(header)
    print(col("─" * (sum(w for _, w in cols)), C.GR))

    def yn(b):
        return col("OK", C.G) if b else col("NO", C.R)

    for r in shown:
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
