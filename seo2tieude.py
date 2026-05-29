"""
域名信息查询工具
查询：网站IP、建站时长、域名到期时间
读取 wangzhi.txt，结果输出到 域名信息.csv
"""

import sys
import csv
import socket
import threading
import time
from pathlib import Path
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import whois
except ImportError:
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "python-whois", "-q"])
    import whois

MAX_WORKERS = 30
print_lock  = threading.Lock()


def log(msg):
    with print_lock:
        print(msg, flush=True)


def get_ip(domain: str) -> str:
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return ""


def clean_domain(url: str) -> str:
    """从网址中提取纯域名"""
    url = url.strip()
    if "://" in url:
        url = url.split("://", 1)[1]
    url = url.split("/")[0].split("?")[0].split("#")[0]
    # 去掉端口
    url = url.split(":")[0]
    return url.lower()


def parse_date(d) -> datetime | None:
    """兼容 whois 返回的各种日期格式"""
    if d is None:
        return None
    if isinstance(d, list):
        d = d[0]
    if isinstance(d, datetime):
        return d
    if isinstance(d, str):
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
            try:
                return datetime.strptime(d[:19], fmt)
            except ValueError:
                continue
    return None


def query(index: int, total: int, url: str) -> dict:
    domain = clean_domain(url)
    result = {
        "url":        url,
        "domain":     domain,
        "ip":         "",
        "registered": "",   # 注册日期
        "expires":    "",   # 到期日期
        "age_years":  "",   # 建站时长（年）
        "error":      "",
    }

    # ── IP 查询（快，先做）──
    result["ip"] = get_ip(domain)

    # ── WHOIS 查询 ──
    try:
        w = whois.whois(domain)

        created = parse_date(w.creation_date)
        expires = parse_date(w.expiration_date)

        if created:
            result["registered"] = created.strftime("%Y-%m-%d")
            now = datetime.now()
            delta = now - created.replace(tzinfo=None)
            years = delta.days / 365.25
            result["age_years"] = f"{years:.1f}"

        if expires:
            result["expires"] = expires.strftime("%Y-%m-%d")

        status = "✅"
        info = f"IP={result['ip'] or '—'}  注册={result['registered'] or '—'}  到期={result['expires'] or '—'}  时长={result['age_years'] or '—'}年"
        log(f"  {status} [{index}/{total}] {domain}  {info}")

    except Exception as e:
        result["error"] = str(e)[:60]
        log(f"  ❌ [{index}/{total}] {domain}  IP={result['ip'] or '—'}  WHOIS失败: {result['error']}")

    return result


def main():
    input_file = Path("wangzhi.txt")
    if not input_file.exists():
        print(f"❌ 找不到 wangzhi.txt（请放在脚本同目录）")
        sys.exit(1)

    urls = [
        line.strip()
        for line in input_file.read_text(encoding="utf-8", errors="ignore").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]

    if not urls:
        print("⚠️  wangzhi.txt 没有有效网址")
        sys.exit(0)

    total   = len(urls)
    workers = min(MAX_WORKERS, total)
    print(f"共 {total} 个域名，{workers} 线程并发查询...\n")

    t0 = time.time()
    results_map = {}

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(query, i + 1, total, url): i
            for i, url in enumerate(urls)
        }
        for future in as_completed(futures):
            results_map[futures[future]] = future.result()

    results = [results_map[i] for i in range(total)]
    elapsed = time.time() - t0

    output_csv = Path("域名信息.csv")
    fields = ["url", "domain", "ip", "registered", "expires", "age_years", "error"]
    with open(output_csv, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(results)

    success = sum(1 for r in results if not r["error"])
    failed  = total - success

    print(f"\n{'='*60}")
    print(f"完成！耗时 {elapsed:.1f}s   ✅ 成功 {success}   ❌ 失败 {failed}")
    print(f"结果已保存：{output_csv.resolve()}")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()