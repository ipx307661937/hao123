#!/usr/bin/env python3
"""中国移动 Cloudflare 特殊线路候选 IP 扫描器。

扫描 Cloudflare 官方 IPv4，将 trace 出口 IP 与本机基准出口不同的地址
识别为中国移动特殊线路候选，并输出 TCPing、线路信息和可选下载测速结果。

运行时主要访问 Cloudflare，并使用国内公网 IP 接口交叉验证基准出口：
- www.cloudflare.com/ips-v4 获取官方 IPv4 网段；
- speed.cloudflare.com/cdn-cgi/trace 获取本机出口和候选 IP 的 trace；
- speedtest.fgfw.eu.org/500m 执行可选下载测速。
- 拓扑兔、3322、DNSPod、花生壳、IPIP.net 用于基准 IPv4 复核。

除可选界面库 Rich 外，脚本只使用 Python 3.11 标准库，
不查询机房位置、国家翻译、ISP、ASN 等数据。
"""

import sys as _bootstrap_sys


def _check_python_runtime() -> None:
    required = (3, 11)
    current = _bootstrap_sys.version_info
    if current >= required:
        return
    print()
    print("Python 版本不符合要求, 脚本无法启动.")
    print(f"当前版本: Python {current.major}.{current.minor}.{current.micro}")
    print("最低要求: Python 3.11")
    print("建议安装: Python 3.11 或 3.12 的 64 位版本")
    print("官方下载: https://www.python.org/downloads/")
    if _bootstrap_sys.platform == "win32":
        print("Windows 安装时请勾选 Add python.exe to PATH.")
        print("安装完成后重新打开命令提示符, 执行 python --version 检查.")
    if _bootstrap_sys.stdin.isatty():
        try:
            input("按回车键关闭窗口...")
        except (EOFError, KeyboardInterrupt):
            pass
    raise SystemExit(1)


_check_python_runtime()

import asyncio
import concurrent.futures
import contextlib
import csv
import hashlib
import http.client
import importlib.util
import ipaddress
import json
import random
import re
import socket
import ssl
import subprocess
import sys
import time
import urllib.parse
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Dict, Iterable, List, Optional, Set, Tuple


SCRIPT_DIR = Path(__file__).resolve().parent
DATA_DIR = SCRIPT_DIR / "cmcc_cf_special_route_data"

CLOUDFLARE_IPV4_URL = "https://www.cloudflare.com/ips-v4"
DOMESTIC_IP_APIS = (
    ("拓扑兔", "http://myipv4.tools.top/"),
    ("3322", "https://ip.3322.net/"),
    ("DNSPod", "https://ipv4.ddnspod.com/"),
    ("花生壳", "http://ddns.oray.com/checkip"),
    ("IPIP.net", "https://myip.ipip.net/json"),
)
TRACE_HOST = "speed.cloudflare.com"
TRACE_PATH = "/cdn-cgi/trace"
DOWNLOAD_HOST = "speedtest.fgfw.eu.org"
DOWNLOAD_PATH = "/500m"
DEFAULT_SPEED_URL = f"https://{DOWNLOAD_HOST}{DOWNLOAD_PATH}"
USER_AGENT = "cmcc-cloudflare-special-route-scanner/4.0"

# Rich 只用于美化界面，缺失时自动尝试安装；安装失败则使用纯文本界面。
# 以后若引入其他第三方包，只需添加
# (导入模块名, pip 包名)，启动时就会自动检查并安装。
REQUIRED_PACKAGES: Tuple[Tuple[str, str], ...] = (("rich", "rich>=13.7"),)
PIP_MIRRORS = (
    ("清华大学", "https://mirrors.tuna.tsinghua.edu.cn/pypi/web/simple"),
    ("阿里云", "https://mirrors.aliyun.com/pypi/simple/"),
)

RICH_CONSOLE = None

CLOUDFLARE_HTTP_PORTS = {80, 8080, 8880, 2052, 2082, 2086, 2095}
CLOUDFLARE_HTTPS_PORTS = {443, 2053, 2083, 2087, 2096, 8443}
IPV4_RE = re.compile(
    r"(?<![\d.])(?:25[0-5]|2[0-4]\d|1?\d?\d)"
    r"(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![\d.])"
)
IGNORED_TRACE_FIELDS = {"uag", "fl", "sliver", "ts"}

CSV_FIELDS = (
    "候选IP",
    "端口",
    "TLS开关",
    "Cloudflare数据中心",
    "出口国家代码",
    "网络延迟(ms)",
    "下载速度(MB/s)",
    "出站IP",
    "出站IP类型",
    "访问协议",
    "HTTP版本",
    "TLS版本",
    "Host",
    "扫描时间",
)


@dataclass(frozen=True)
class Endpoint:
    port: int
    tls: bool

    @property
    def scheme(self) -> str:
        return "https" if self.tls else "http"

    @property
    def key(self) -> str:
        return f"{self.port}:{self.scheme}"


@dataclass
class TraceResponse:
    status: int
    headers: Dict[str, str]
    trace: Dict[str, str]
    tcp_ms: float
    connect_ms: float
    ttfb_ms: float
    total_ms: float


@dataclass
class ProbeResult:
    index: int
    target_ip: str
    endpoint: Endpoint
    ok: bool
    match: bool = False
    record: Optional[dict] = None
    error: Optional[str] = None


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def init_rich_ui() -> None:
    global RICH_CONSOLE
    try:
        from rich.console import Console

        RICH_CONSOLE = Console(highlight=False, safe_box=True, emoji=False)
    except ImportError:
        RICH_CONSOLE = None


def ui_print(message: object = "", **kwargs: object) -> None:
    if RICH_CONSOLE is not None:
        RICH_CONSOLE.print(message, **kwargs)
    else:
        print(message, **kwargs)


def ensure_dependencies() -> None:
    missing = [
        (module_name, package_name)
        for module_name, package_name in REQUIRED_PACKAGES
        if importlib.util.find_spec(module_name) is None
    ]
    if not missing:
        return
    packages = [package_name for _, package_name in missing]
    print(f"检测到缺失依赖: {', '.join(packages)}")
    errors = []
    for mirror_name, mirror_url in PIP_MIRRORS:
        print(f"正在使用{mirror_name}镜像安装...")
        command = [
            sys.executable,
            "-m",
            "pip",
            "install",
            "--disable-pip-version-check",
            "--timeout",
            "15",
            "--retries",
            "1",
            "--index-url",
            mirror_url,
            *packages,
        ]
        try:
            subprocess.check_call(command)
            print(f"依赖已通过{mirror_name}镜像安装完成.")
            return
        except (OSError, subprocess.CalledProcessError) as exc:
            errors.append(f"{mirror_name}: {exc}")
            print(f"{mirror_name}镜像安装失败, 正在尝试下一个国内镜像.")
    print("所有国内镜像均安装失败, 程序将使用纯文本兼容界面继续运行.")
    for error in errors:
        print(f"  {error}")


def prompt_text(label: str, default: str) -> str:
    if RICH_CONSOLE is not None:
        from rich.prompt import Prompt

        return Prompt.ask(label, default=default, console=RICH_CONSOLE).strip()
    value = input(f"{label} [{default}]：").strip()
    return value or default


def prompt_int(label: str, default: int, minimum: int = 1) -> int:
    while True:
        value = prompt_text(label, str(default))
        try:
            number = int(value)
            if number < minimum:
                raise ValueError
            return number
        except ValueError:
            print(f"请输入不小于 {minimum} 的整数。")


def prompt_float(label: str, default: float, minimum: float = 0.0) -> float:
    while True:
        value = prompt_text(label, f"{default:g}")
        try:
            number = float(value)
            if number <= minimum:
                raise ValueError
            return number
        except ValueError:
            print(f"请输入大于 {minimum:g} 的数字。")


def prompt_yes_no(label: str, default: bool = False) -> bool:
    if RICH_CONSOLE is not None:
        from rich.prompt import Confirm

        return Confirm.ask(label, default=default, console=RICH_CONSOLE)
    hint = "Y/n" if default else "y/N"
    while True:
        value = input(f"{label} [{hint}]：").strip().lower()
        if not value:
            return default
        if value in ("y", "yes", "1", "是"):
            return True
        if value in ("n", "no", "0", "否"):
            return False
        print("请输入 y 或 n。")


def print_brand_banner() -> None:
    logo_lines = (
        "DDDD    FFFFFF",
        "D   D   FF    ",
        "D   D   FFFF  ",
        "D   D   FF    ",
        "DDDD    FF    ",
        "D A N F E N G ",
    )
    if RICH_CONSOLE is not None:
        from rich import box
        from rich.align import Align
        from rich.console import Group
        from rich.panel import Panel
        from rich.text import Text

        logo = Text()
        for index, line in enumerate(logo_lines):
            logo.append(line.rstrip(), style="bold bright_red" if index < 5 else "bold orange1")
            if index < len(logo_lines) - 1:
                logo.append("\n")
        content = Group(
            Align.center(logo),
            Align.center(Text("中国移动 Cloudflare 特殊线路扫描器", style="bold cyan")),
            Align.center(Text("来源: DanFeng交流群", style="bold white")),
            Align.center(Text("https://t.me/danfeng_chat", style="bold bright_blue")),
        )
        RICH_CONSOLE.print()
        RICH_CONSOLE.print(
            Panel.fit(
                content,
                border_style="bright_red",
                padding=(1, 3),
                box=box.ASCII,
            )
        )
        return

    print()
    print("+--------------------------------------------------+")
    logo_width = max(len(line.rstrip()) for line in logo_lines)
    logo_indent = " " * ((50 - logo_width) // 2)
    for line in logo_lines:
        print(logo_indent + line.rstrip())
    print("中国移动 Cloudflare 特殊线路扫描器".center(42))
    print("来源: DanFeng交流群".center(42))
    print("https://t.me/danfeng_chat".center(50))
    print("+--------------------------------------------------+")


def configure_interactively(args: SimpleNamespace) -> SimpleNamespace:
    print_brand_banner()
    if RICH_CONSOLE is not None:
        from rich.table import Table

        RICH_CONSOLE.print(
            "[dim]交叉验证基准出口 - 发现特殊线路候选 IP - 可选下载测速[/dim]"
        )
        mode_table = Table(show_header=False, box=None, padding=(0, 1))
        mode_table.add_row(
            "[bold green]1[/bold green]",
            "一键运行",
            "[dim]随机 20000 IP / 443 / speed.cloudflare.com / 扫描并发 100 / 超时 3 秒 / 测速并发 2[/dim]",
        )
        mode_table.add_row(
            "[bold yellow]2[/bold yellow]",
            "自定义参数",
            "[dim]自行设置扫描范围、端口、Host、并发和测速[/dim]",
        )
        RICH_CONSOLE.print("\n[bold]运行模式[/bold]")
        RICH_CONSOLE.print(mode_table)
    else:
        print("交叉验证基准出口 - 发现特殊线路候选 IP - 可选下载测速")
        print("运行模式:")
        print("  1. 一键运行")
        print("     随机 20000 IP, 443 端口, speed.cloudflare.com")
        print("     扫描并发 100, 单项超时 3 秒, 开启测速, 测速并发 2")
        print("  2. 自定义参数")
    while True:
        mode = prompt_text("请选择", "1")
        if mode in ("1", "onekey", "一键", "一键运行"):
            args.run_mode = "onekey"
            args.scan_mode = "random"
            args.sample_size = 20000
            args.reuse_sample = False
            args.resume_scan = False
            args.resume_state = None
            args.skip_resume_checkpoint = True
            args.port = None
            args.ports = "443"
            args.host = TRACE_HOST
            args.tls = True
            args.auto_protocol = True
            args.concurrency = 100
            args.timeout = 3.0
            args.speedtest = True
            args.speed_concurrency = 2
            args.speed_url = DEFAULT_SPEED_URL
            args.speed_host, args.speed_path = parse_speed_url(args.speed_url)
            args.start_index = 0
            ui_print(
                "[green]已启用一键运行模式. 下面仅需确认基准出口 IPv4.[/green]"
                if RICH_CONSOLE
                else "已启用一键运行模式. 下面仅需确认基准出口 IPv4."
            )
            return args
        if mode in ("2", "custom", "自定义", "自定义参数"):
            args.run_mode = "custom"
            break
        ui_print("[red]请输入 1 或 2。[/red]" if RICH_CONSOLE else "请输入 1 或 2。")

    if RICH_CONSOLE is not None:
        from rich.table import Table

        scan_table = Table(show_header=False, box=None, padding=(0, 1))
        scan_table.add_row("[bold green]1[/bold green]", "随机抽取 IP", "[dim]快速发现移动特殊线路候选[/dim]")
        scan_table.add_row("[bold yellow]2[/bold yellow]", "全量扫描", "[dim]耗时较长，支持断点续扫[/dim]")
        RICH_CONSOLE.print("\n[bold]扫描范围[/bold]")
        RICH_CONSOLE.print(scan_table)
    else:
        print("\n扫描范围:")
        print("  1. 随机抽取 IP")
        print("  2. 全量扫描全部 Cloudflare IPv4")
    while True:
        scan_mode = prompt_text("请选择", "1")
        if scan_mode in ("1", "random", "随机"):
            args.scan_mode = "random"
            args.sample_size = prompt_int("随机抽取多少个 IP", 10000)
            args.reuse_sample = False
            args.resume_scan = False
            args.resume_state = None
            args.skip_resume_checkpoint = True
            args.start_index = 0
            break
        if scan_mode in ("2", "full", "全量"):
            args.scan_mode = "full"
            args.sample_size = None
            args.reuse_sample = False
            args.resume_scan = False
            args.skip_resume_checkpoint = False
            checkpoint_state = read_checkpoint_file(Path(args.checkpoint))
            if checkpoint_state and not checkpoint_state.get("completed", False):
                saved_config = checkpoint_state.get("scan_config")
                saved_output_text = str(checkpoint_state.get("output_file", "")).strip()
                saved_output = Path(saved_output_text) if saved_output_text else None
                if isinstance(saved_config, dict) and saved_output and saved_output.exists():
                    show_resume_config(checkpoint_state, saved_config)
                    phase = checkpoint_state.get("phase", "scan")
                    prompt = (
                        "检测到上次扫描已完成但测速未完成, 是否继续测速并复用以上配置"
                        if phase == "speedtest"
                        else "是否继续上次全量扫描并复用以上配置"
                    )
                    if prompt_yes_no(prompt, True):
                        apply_saved_scan_config(args, saved_config)
                        args.resume_scan = True
                        args.resume_state = checkpoint_state
                        ui_print(
                            "[green]已恢复上次全量扫描配置. 下面仅需重新确认基准出口 IPv4.[/green]"
                            if RICH_CONSOLE
                            else "已恢复上次全量扫描配置. 下面仅需重新确认基准出口 IPv4."
                        )
                        return args
                    args.skip_resume_checkpoint = True
            break
        ui_print("[red]请输入 1 或 2。[/red]" if RICH_CONSOLE else "请输入 1 或 2。")

    if RICH_CONSOLE is not None:
        RICH_CONSOLE.print(
            "\n[bold]端口配置[/bold]\n"
            "[dim]多个端口用逗号分隔；常见端口自动识别协议。"
            "也可显式输入 443:https,80:http,2053:https[/dim]"
        )
    else:
        print("\n端口可用逗号分隔；常见 Cloudflare 端口会自动识别协议。")
        print("也可以显式输入 443:https,80:http,2053:https")
    args.ports = prompt_text("请输入端口", "443")
    args.port = None
    args.auto_protocol = True
    while True:
        try:
            args.host = normalize_test_host(
                prompt_text(
                    "请输入测试 Host (必须为托管在 Cloudflare 的网站)",
                    args.host,
                )
            )
            break
        except ValueError as exc:
            ui_print(
                f"[red]Host 无效: {exc}[/red]"
                if RICH_CONSOLE
                else f"Host 无效: {exc}"
            )
    args.concurrency = prompt_int("并发数", 100)
    args.timeout = prompt_float("单个地址超时（秒）", 3.0)
    args.speedtest = prompt_yes_no("是否对特殊线路候选执行下载测速", False)
    if args.speedtest:
        while True:
            try:
                args.speed_url = prompt_text("请输入测速链接", DEFAULT_SPEED_URL)
                args.speed_host, args.speed_path = parse_speed_url(args.speed_url)
                args.speed_url = f"https://{args.speed_host}{args.speed_path}"
                break
            except ValueError as exc:
                ui_print(
                    f"[red]测速链接无效: {exc}[/red]"
                    if RICH_CONSOLE
                    else f"测速链接无效: {exc}"
                )
        ui_print(
            f"[dim]测速地址：{args.speed_url}；"
            f"每个候选地址持续 {args.speed_duration:g} 秒。[/dim]"
            if RICH_CONSOLE
            else f"测速地址：{args.speed_url}，每个候选地址持续 {args.speed_duration:g} 秒。"
        )
        args.speed_concurrency = prompt_int("测速并发数", 3)
    ui_print()
    return args


def direct_urlopen(url: str, timeout: float, redirects: int = 3) -> bytes:
    """强制使用 IPv4 直连 HTTP(S)，避免查询接口返回本机 IPv6。"""
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError(f"不支持的 URL: {url}")
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = urllib.parse.urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
    default_port = 443 if parsed.scheme == "https" else 80
    host_header_value = host if port == default_port else f"{host}:{port}"
    infos = socket.getaddrinfo(
        host, port, family=socket.AF_INET, type=socket.SOCK_STREAM
    )
    addresses = []
    for info in infos:
        address = info[4][0]
        if address not in addresses:
            addresses.append(address)
    if not addresses:
        raise OSError(f"{host} 没有 IPv4 DNS 记录")

    errors = []
    for address in addresses:
        connection = None
        response = None
        try:
            connection = socket.create_connection((address, port), timeout=timeout)
            connection.settimeout(timeout)
            if parsed.scheme == "https":
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                connection = context.wrap_socket(connection, server_hostname=host)
            request = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {host_header_value}\r\n"
                f"User-Agent: {USER_AGENT}\r\n"
                "Accept: */*\r\n"
                "Accept-Encoding: identity\r\n"
                "Connection: close\r\n\r\n"
            ).encode("ascii")
            connection.sendall(request)
            response = http.client.HTTPResponse(connection)
            response.begin()
            if response.status in (301, 302, 303, 307, 308):
                location = response.getheader("Location")
                if not location or redirects <= 0:
                    raise OSError(f"HTTP {response.status} 重定向无效")
                redirect_url = urllib.parse.urljoin(url, location)
                response.close()
                response = None
                connection.close()
                connection = None
                return direct_urlopen(redirect_url, timeout, redirects - 1)
            if response.status >= 400:
                raise OSError(f"HTTP {response.status} {response.reason}")
            body = response.read(1024 * 1024 + 1)
            if len(body) > 1024 * 1024:
                raise ValueError("HTTP 响应超过 1 MB")
            return body
        except Exception as exc:
            errors.append(f"{address}: {type(exc).__name__}: {exc}")
        finally:
            if response is not None:
                response.close()
            if connection is not None:
                with contextlib.suppress(Exception):
                    connection.close()
    raise OSError("; ".join(errors))


def parse_public_ipv4(value: str) -> ipaddress.IPv4Address:
    address = ipaddress.ip_address(value.strip())
    if not isinstance(address, ipaddress.IPv4Address):
        raise ValueError(f"不是 IPv4：{value}")
    if not address.is_global:
        raise ValueError(f"不是公网 IPv4：{address}")
    return address


def normalize_test_host(value: str) -> str:
    host = value.strip().rstrip(".")
    if not host:
        raise ValueError("Host 不能为空")
    if "://" in host or "/" in host or ":" in host or any(ch.isspace() for ch in host):
        raise ValueError("只输入域名, 不要包含协议、端口或路径")
    try:
        ipaddress.ip_address(host)
        raise ValueError("测试 Host 必须是托管在 Cloudflare 的域名, 不能直接输入 IP")
    except ValueError as exc:
        if "必须是托管" in str(exc):
            raise
    try:
        ascii_host = host.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("域名格式无效") from exc
    if len(ascii_host) > 253:
        raise ValueError("域名长度超过限制")
    label_pattern = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
    labels = ascii_host.split(".")
    if len(labels) < 2 or any(not label_pattern.fullmatch(label) for label in labels):
        raise ValueError("域名格式无效")
    return ascii_host


def parse_speed_url(value: str) -> Tuple[str, str]:
    text = value.strip()
    if not text:
        raise ValueError("测速链接不能为空")
    parsed = urllib.parse.urlsplit(text)
    if parsed.scheme.lower() != "https":
        raise ValueError("测速链接必须使用 https")
    if not parsed.hostname:
        raise ValueError("测速链接缺少域名")
    if parsed.username or parsed.password or parsed.fragment:
        raise ValueError("测速链接不能包含账号、密码或片段")
    if parsed.port not in (None, 443):
        raise ValueError("测速链接目前只支持 HTTPS 443 端口")
    host = normalize_test_host(parsed.hostname)
    path = urllib.parse.urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
    return host, path


async def validate_cloudflare_host(
    host: str, networks: List[ipaddress.IPv4Network]
) -> List[ipaddress.IPv4Address]:
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(
        host,
        443,
        family=socket.AF_INET,
        type=socket.SOCK_STREAM,
    )
    addresses: List[ipaddress.IPv4Address] = []
    for info in infos:
        address = ipaddress.IPv4Address(info[4][0])
        if address not in addresses:
            addresses.append(address)
    if not addresses:
        raise ValueError("域名没有可用的 IPv4 DNS 记录")
    cloudflare_addresses = [
        address
        for address in addresses
        if any(address in network for network in networks)
    ]
    if not cloudflare_addresses:
        resolved = ", ".join(str(address) for address in addresses)
        raise ValueError(
            f"域名解析结果不在 Cloudflare 官方 IPv4 网段内: {resolved}"
        )
    return cloudflare_addresses


def query_domestic_egress_ipv4s(
    timeout: float,
) -> Tuple[List[Tuple[str, ipaddress.IPv4Address]], List[str]]:
    def query_one(item: Tuple[str, str]):
        name, url = item
        try:
            body = direct_urlopen(url, timeout).decode("utf-8", errors="replace")
            match = IPV4_RE.search(body)
            if not match:
                preview = " ".join(body[:160].split())
                raise ValueError(f"响应中没有 IPv4, 内容: {preview}")
            return name, parse_public_ipv4(match.group(0)), None
        except Exception as exc:
            return name, None, f"{name}: {type(exc).__name__}: {exc}"

    successes: List[Tuple[str, ipaddress.IPv4Address]] = []
    errors: List[str] = []
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=len(DOMESTIC_IP_APIS)
    ) as executor:
        results = executor.map(query_one, DOMESTIC_IP_APIS)
        for name, address, error in results:
            if address is not None:
                successes.append((name, address))
            elif error:
                errors.append(error)
    return successes, errors


def prompt_manual_baseline() -> ipaddress.IPv4Address:
    while True:
        value = input("请输入确认后的公网 IPv4（输入 q 退出）：").strip()
        if value.lower() in ("q", "quit", "exit"):
            raise KeyboardInterrupt
        try:
            return parse_public_ipv4(value)
        except ValueError as exc:
            print(f"输入无效：{exc}")


def select_baseline_ip(
    cloudflare_ip: ipaddress.IPv4Address,
    domestic_results: List[Tuple[str, ipaddress.IPv4Address]],
    domestic_errors: List[str],
    interactive: bool,
    override: Optional[str],
) -> ipaddress.IPv4Address:
    if RICH_CONSOLE is not None:
        from rich import box
        from rich.table import Table

        table = Table(
            title="基准出口 IPv4 交叉验证",
            header_style="bold cyan",
            border_style="cyan",
            box=box.ASCII,
        )
        table.add_column("来源")
        table.add_column("检测结果", style="bold")
        table.add_column("状态", justify="center")
        table.add_row("Cloudflare /cdn-cgi/trace", str(cloudflare_ip), "[green]成功[/green]")
        for name, address in domestic_results:
            table.add_row(name, str(address), "[green]成功[/green]")
        for error in domestic_errors:
            name, _, detail = error.partition(":")
            table.add_row(name, detail.strip(), "[red]失败[/red]")
        RICH_CONSOLE.print(table)
    else:
        print("\n基准出口 IPv4 交叉验证：")
        print(f"  Cloudflare /cdn-cgi/trace：{cloudflare_ip}")
        for name, address in domestic_results:
            print(f"  {name}：{address}")
        for error in domestic_errors:
            print(f"  查询失败：{error}")

    if override:
        selected = parse_public_ipv4(override)
        ui_print(
            f"[cyan]使用命令行指定的基准 IP：[/cyan][bold]{selected}[/bold]"
            if RICH_CONSOLE
            else f"使用命令行指定的基准 IP：{selected}"
        )
        return selected

    matching_domestic = [
        name for name, address in domestic_results if address == cloudflare_ip
    ]
    if not interactive:
        if not matching_domestic:
            raise RuntimeError(
                "Cloudflare trace 与国内接口未能取得一致结果；"
                "请在交互界面中手动确认基准 IP"
            )
        ui_print(
            f"[green]基准 IP 已由 Cloudflare 与 {', '.join(matching_domestic)} 共同确认。[/green]"
            if RICH_CONSOLE
            else f"基准 IP 已由 Cloudflare 与 {', '.join(matching_domestic)} 共同确认。"
        )
        return cloudflare_ip

    unique_candidates: List[Tuple[str, ipaddress.IPv4Address]] = [
        ("Cloudflare trace", cloudflare_ip)
    ]
    for name, address in domestic_results:
        if all(existing != address for _, existing in unique_candidates):
            unique_candidates.append((name, address))

    if matching_domestic:
        ui_print(
            f"[green]Cloudflare 与 {', '.join(matching_domestic)} 结果一致[/green]，"
            f"建议基准 IP：[bold cyan]{cloudflare_ip}[/bold cyan]"
            if RICH_CONSOLE
            else f"Cloudflare 与 {', '.join(matching_domestic)} 结果一致，建议基准 IP：{cloudflare_ip}"
        )
        if prompt_yes_no("确认使用这个基准 IP", True):
            return cloudflare_ip
        return prompt_manual_baseline()

    ui_print(
        "[bold red]警告：Cloudflare trace 与国内接口结果不一致，不能自动开始扫描。[/bold red]"
        if RICH_CONSOLE
        else "警告：Cloudflare trace 与国内接口结果不一致，不能自动开始扫描。"
    )
    for index, (name, address) in enumerate(unique_candidates, 1):
        print(f"  {index}. 使用 {name} 的结果：{address}")
    print("  m. 手动输入基准 IP")
    print("  q. 退出")
    while True:
        choice = input("请选择基准 IP：").strip().lower()
        if choice == "m":
            return prompt_manual_baseline()
        if choice in ("q", "quit", "exit"):
            raise KeyboardInterrupt
        try:
            selected_index = int(choice) - 1
            if 0 <= selected_index < len(unique_candidates):
                selected = unique_candidates[selected_index][1]
                if prompt_yes_no(f"确认使用 {selected} 作为基准 IP", False):
                    return selected
        except ValueError:
            pass
        print("请选择有效序号、m 或 q。")


def fetch_cloudflare_networks(url: str, timeout: float) -> List[ipaddress.IPv4Network]:
    text = direct_urlopen(url, timeout).decode("utf-8", errors="strict")
    networks: List[ipaddress.IPv4Network] = []
    seen: Set[str] = set()
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        network = ipaddress.ip_network(line, strict=True)
        if network.version == 4 and str(network) not in seen:
            seen.add(str(network))
            networks.append(network)
    if not networks:
        raise RuntimeError("Cloudflare IPv4 地址列表为空")
    return networks


def parse_endpoints(args: SimpleNamespace) -> List[Endpoint]:
    if args.port and args.ports:
        raise ValueError("端口配置冲突")
    if args.port:
        tokens = [str(port) for port in args.port]
    elif args.ports:
        normalized_ports = (
            args.ports.replace("，", ",").replace(";", ",").replace("；", ",").replace(" ", ",")
        )
        tokens = [part.strip() for part in normalized_ports.split(",") if part.strip()]
    else:
        tokens = ["443" if args.tls else "80"]

    endpoints: List[Endpoint] = []
    seen: Set[Tuple[int, bool]] = set()
    for token in tokens:
        if ":" in token:
            port_text, protocol = token.rsplit(":", 1)
            protocol = protocol.lower()
            if protocol in ("https", "tls", "true", "1"):
                tls = True
            elif protocol in ("http", "plain", "false", "0"):
                tls = False
            else:
                raise ValueError(f"未知端口协议：{token}")
        else:
            port_text = token
            port_number = int(port_text)
            if args.auto_protocol and port_number in CLOUDFLARE_HTTP_PORTS:
                tls = False
            elif args.auto_protocol and port_number in CLOUDFLARE_HTTPS_PORTS:
                tls = True
            else:
                tls = args.tls
        port = int(port_text)
        if not 1 <= port <= 65535:
            raise ValueError(f"端口超出范围：{port}")
        key = (port, tls)
        if key not in seen:
            seen.add(key)
            endpoints.append(Endpoint(port, tls))
    if not endpoints:
        raise ValueError("没有可扫描的端口")
    return endpoints


def ranges_fingerprint(networks: Iterable[ipaddress.IPv4Network]) -> str:
    return hashlib.sha256(
        "\n".join(str(item) for item in networks).encode("ascii")
    ).hexdigest()


def scan_fingerprint(
    networks: Iterable[ipaddress.IPv4Network],
    endpoints: Iterable[Endpoint],
    sampled_ip_indices: Optional[Iterable[int]],
    test_host: str,
) -> str:
    parts = [str(item) for item in networks]
    parts.extend(endpoint.key for endpoint in endpoints)
    parts.append(f"host={test_host}")
    if sampled_ip_indices is None:
        parts.append("mode=full")
    else:
        parts.append("mode=random")
        parts.extend(str(index) for index in sampled_ip_indices)
    return hashlib.sha256("\n".join(parts).encode("ascii")).hexdigest()


def load_or_create_sample(
    networks: List[ipaddress.IPv4Network],
    sample_size: int,
    sample_path: Path,
    reuse: bool,
) -> List[int]:
    total = sum(network.num_addresses for network in networks)
    if sample_size > total:
        print(f"随机数量超过地址总数，自动调整为 {total}。", file=sys.stderr)
        sample_size = total
    current_ranges = ranges_fingerprint(networks)
    if reuse and sample_path.exists():
        try:
            state = json.loads(sample_path.read_text(encoding="utf-8"))
            indices = [int(value) for value in state.get("indices", [])]
            if (
                state.get("ranges_sha256") == current_ranges
                and len(indices) == sample_size
                and all(0 <= value < total for value in indices)
            ):
                print(f"继续使用上次保存的 {sample_size} 个随机 IP。", file=sys.stderr)
                return indices
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            pass
        print("上次随机样本无效，将重新抽取。", file=sys.stderr)

    indices = sorted(random.SystemRandom().sample(range(total), sample_size))
    sample_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = sample_path.with_suffix(sample_path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(
            {
                "ranges_sha256": current_ranges,
                "sample_size": sample_size,
                "indices": indices,
                "created_at": utc_now(),
            },
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )
    temporary.replace(sample_path)
    print(f"已随机抽取并保存 {sample_size} 个 IP。", file=sys.stderr)
    return indices


def iter_ip_targets(
    networks: Iterable[ipaddress.IPv4Network], start_ip_index: int
) -> Iterable[Tuple[int, str]]:
    global_offset = 0
    for network in networks:
        count = network.num_addresses
        if global_offset + count <= start_ip_index:
            global_offset += count
            continue
        local_start = max(0, start_ip_index - global_offset)
        base = int(network.network_address)
        for local_index in range(local_start, count):
            yield global_offset + local_index, str(ipaddress.IPv4Address(base + local_index))
        global_offset += count


def iter_scan_targets(
    networks: Iterable[ipaddress.IPv4Network],
    endpoints: List[Endpoint],
    start_index: int,
    limit: Optional[int],
    sampled_ip_indices: Optional[List[int]] = None,
) -> Iterable[Tuple[int, str, Endpoint]]:
    endpoint_count = len(endpoints)
    start_ip_index, start_endpoint_index = divmod(start_index, endpoint_count)
    emitted = 0
    network_list = list(networks)
    if sampled_ip_indices is None:
        targets = iter_ip_targets(network_list, start_ip_index)
    else:
        def sampled_targets() -> Iterable[Tuple[int, str]]:
            for sample_position in range(start_ip_index, len(sampled_ip_indices)):
                global_ip_index = sampled_ip_indices[sample_position]
                remaining = global_ip_index
                for network in network_list:
                    if remaining < network.num_addresses:
                        address = ipaddress.IPv4Address(
                            int(network.network_address) + remaining
                        )
                        yield sample_position, str(address)
                        break
                    remaining -= network.num_addresses

        targets = sampled_targets()
    for ip_index, target_ip in targets:
        first_endpoint = start_endpoint_index if ip_index == start_ip_index else 0
        for endpoint_index in range(first_endpoint, endpoint_count):
            if limit is not None and emitted >= limit:
                return
            index = ip_index * endpoint_count + endpoint_index
            yield index, target_ip, endpoints[endpoint_index]
            emitted += 1


def parse_http_headers(header_blob: bytes) -> Tuple[int, Dict[str, str]]:
    lines = header_blob.decode("iso-8859-1", errors="replace").split("\r\n")
    status_parts = lines[0].split(" ", 2)
    if len(status_parts) < 2 or not status_parts[1].isdigit():
        raise ValueError(f"无效 HTTP 状态行: {lines[0]!r}")
    status = int(status_parts[1])
    headers: Dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip().lower()] = value.strip()
    return status, headers


def parse_http_response(raw: bytes) -> Tuple[int, Dict[str, str], bytes]:
    header_blob, separator, body = raw.partition(b"\r\n\r\n")
    if not separator:
        raise ValueError("HTTP 响应头不完整")
    status, headers = parse_http_headers(header_blob)
    if "chunked" in headers.get("transfer-encoding", "").lower():
        body = decode_chunked(body)
    return status, headers, body


def decode_chunked(data: bytes) -> bytes:
    output = bytearray()
    position = 0
    while True:
        line_end = data.find(b"\r\n", position)
        if line_end < 0:
            raise ValueError("不完整的 chunk 长度")
        size = int(data[position:line_end].split(b";", 1)[0], 16)
        position = line_end + 2
        if size == 0:
            return bytes(output)
        chunk_end = position + size
        if chunk_end + 2 > len(data):
            raise ValueError("不完整的 chunk 数据")
        output.extend(data[position:chunk_end])
        position = chunk_end + 2


def parse_trace(body: bytes) -> Dict[str, str]:
    trace: Dict[str, str] = {}
    for line in body.decode("utf-8", errors="replace").splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            normalized_key = key.strip()
            if normalized_key and normalized_key not in IGNORED_TRACE_FIELDS:
                trace[normalized_key] = value.strip()
    return trace


async def read_chunked_stream(
    reader: asyncio.StreamReader, max_body_bytes: int
) -> bytes:
    output = bytearray()
    while True:
        size_line = await reader.readline()
        if not size_line:
            raise ValueError("chunked 响应提前结束")
        size_text = size_line.strip().split(b";", 1)[0]
        size = int(size_text, 16)
        if size == 0:
            while True:
                trailer = await reader.readline()
                if trailer in (b"\r\n", b"\n", b""):
                    return bytes(output)
        if len(output) + size > max_body_bytes:
            raise ValueError("HTTP 正文超过允许大小")
        output.extend(await reader.readexactly(size))
        if await reader.readexactly(2) != b"\r\n":
            raise ValueError("chunked 响应格式错误")


async def read_http_message(
    reader: asyncio.StreamReader,
    max_body_bytes: int,
    idle_timeout: float = 0.3,
) -> Tuple[int, Dict[str, str], bytes, float]:
    first_byte = await reader.readexactly(1)
    first_byte_at = time.perf_counter()
    header_tail = await reader.readuntil(b"\r\n\r\n")
    header_blob = first_byte + header_tail[:-4]
    status, headers = parse_http_headers(header_blob)

    transfer_encoding = headers.get("transfer-encoding", "").lower()
    content_length_text = headers.get("content-length")
    if "chunked" in transfer_encoding:
        body = await read_chunked_stream(reader, max_body_bytes)
    elif content_length_text is not None:
        content_length = int(content_length_text)
        if content_length < 0 or content_length > max_body_bytes:
            raise ValueError("HTTP Content-Length 超过允许大小")
        body = await reader.readexactly(content_length)
    else:
        chunks = []
        size = 0
        while size < max_body_bytes:
            try:
                chunk = await asyncio.wait_for(
                    reader.read(min(8192, max_body_bytes - size)),
                    timeout=idle_timeout,
                )
            except asyncio.TimeoutError:
                break
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
        body = b"".join(chunks)
    return status, headers, body, first_byte_at


def host_header(hostname: str, endpoint: Endpoint) -> str:
    default_port = 443 if endpoint.tls else 80
    return hostname if endpoint.port == default_port else f"{hostname}:{endpoint.port}"


def build_ssl_context(insecure: bool) -> ssl.SSLContext:
    context = ssl.create_default_context()
    context.set_alpn_protocols(["http/1.1"])
    if insecure:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context


async def open_target(
    target_ip: str,
    endpoint: Endpoint,
    ssl_context: ssl.SSLContext,
    hostname: str,
    connect_timeout: float,
    handshake_timeout: float,
) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter, float]:
    tcp_started = time.perf_counter()
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(host=target_ip, port=endpoint.port),
        timeout=connect_timeout,
    )
    tcp_ms = round((time.perf_counter() - tcp_started) * 1000, 2)
    if not endpoint.tls:
        return reader, writer, tcp_ms
    try:
        await writer.start_tls(
            ssl_context,
            server_hostname=hostname,
            ssl_handshake_timeout=handshake_timeout,
        )
        return reader, writer, tcp_ms
    except Exception:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
        raise


async def request_trace(
    target_ip: str,
    endpoint: Endpoint,
    ssl_context: ssl.SSLContext,
    timeout: float,
    connect_timeout: float,
    hostname: str = TRACE_HOST,
) -> TraceResponse:
    writer: Optional[asyncio.StreamWriter] = None
    started = time.perf_counter()

    async def operation() -> TraceResponse:
        nonlocal writer
        reader, writer, tcp_ms = await open_target(
            target_ip,
            endpoint,
            ssl_context,
            hostname,
            connect_timeout,
            min(2.0, timeout),
        )
        connected = time.perf_counter()
        request = (
            f"GET {TRACE_PATH} HTTP/1.1\r\n"
            f"Host: {host_header(hostname, endpoint)}\r\n"
            f"User-Agent: {USER_AGENT}\r\n"
            "Accept: text/plain\r\n"
            "Accept-Encoding: identity\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii")
        writer.write(request)
        await writer.drain()
        status, headers, body, first_byte_at = await read_http_message(
            reader, 64 * 1024
        )
        finished = time.perf_counter()
        if status != 200:
            raise ValueError(f"HTTP {status}")
        trace = parse_trace(body)
        if not trace.get("ip"):
            raise ValueError("trace 响应缺少 ip 字段")
        return TraceResponse(
            status=status,
            headers=headers,
            trace=trace,
            tcp_ms=tcp_ms,
            connect_ms=round((connected - started) * 1000, 2),
            ttfb_ms=round((first_byte_at - started) * 1000, 2),
            total_ms=round((finished - started) * 1000, 2),
        )

    try:
        return await asyncio.wait_for(operation(), timeout=timeout)
    finally:
        if writer is not None:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()


async def get_cloudflare_egress_ipv4(
    ssl_context: ssl.SSLContext, timeout: float, connect_timeout: float
) -> Tuple[ipaddress.IPv4Address, str]:
    """通过正常 DNS 解析后的 Cloudflare IPv4 获取本机出口 IPv4。"""
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(
        TRACE_HOST,
        443,
        family=socket.AF_INET,
        type=socket.SOCK_STREAM,
    )
    addresses = []
    for info in infos:
        address = info[4][0]
        if address not in addresses:
            addresses.append(address)
    errors = []
    for address in addresses:
        try:
            response = await request_trace(
                address,
                Endpoint(443, True),
                ssl_context,
                timeout,
                connect_timeout,
            )
            exit_ip = parse_public_ipv4(response.trace["ip"])
            return exit_ip, address
        except Exception as exc:
            errors.append(f"{address}: {exc}")
    raise RuntimeError("无法通过 Cloudflare trace 获取本机出口 IPv4；" + "；".join(errors))


class BaselineGuard:
    def __init__(
        self,
        expected_cloudflare_ip: ipaddress.IPv4Address,
        expected_domestic: List[Tuple[str, ipaddress.IPv4Address]],
        ssl_context: ssl.SSLContext,
        timeout: float,
        connect_timeout: float,
        interval: float,
    ) -> None:
        self.expected_cloudflare_ip = expected_cloudflare_ip
        self.expected_domestic = dict(expected_domestic)
        self.ssl_context = ssl_context
        self.timeout = timeout
        self.connect_timeout = connect_timeout
        self.interval = interval
        self.next_check = time.monotonic() + interval
        self.lock = asyncio.Lock()
        self.abort_event = asyncio.Event()
        self.error: Optional[str] = None

    async def maybe_check(self) -> None:
        if self.interval <= 0 or time.monotonic() < self.next_check:
            return
        async with self.lock:
            if self.error:
                raise RuntimeError(self.error)
            if time.monotonic() < self.next_check:
                return
            try:
                current_cloudflare, _ = await get_cloudflare_egress_ipv4(
                    self.ssl_context, self.timeout, self.connect_timeout
                )
                current_domestic, domestic_errors = await asyncio.to_thread(
                    query_domestic_egress_ipv4s, self.timeout
                )
                changes = []
                if current_cloudflare != self.expected_cloudflare_ip:
                    changes.append(
                        f"Cloudflare trace: {self.expected_cloudflare_ip} -> {current_cloudflare}"
                    )
                current_domestic_map = dict(current_domestic)
                for name, expected in self.expected_domestic.items():
                    current = current_domestic_map.get(name)
                    if current is not None and current != expected:
                        changes.append(f"{name}: {expected} -> {current}")
                if changes:
                    self.error = "检测到出口 IP 变化：" + "；".join(changes)
                    self.abort_event.set()
                    ui_print(
                        f"[bold red]基准保护触发：{self.error}[/bold red]"
                        if RICH_CONSOLE
                        else f"\n基准保护触发：{self.error}"
                    )
                    raise RuntimeError(self.error)
                if not current_domestic:
                    ui_print(
                        "[yellow]基准复查警告：国内接口本次全部不可用；"
                        "Cloudflare trace 未变化，暂时继续。[/yellow]"
                        if RICH_CONSOLE
                        else "\n基准复查警告：国内接口本次全部不可用；Cloudflare trace 未变化，暂时继续。"
                    )
                    for error in domestic_errors:
                        print(f"  {error}", file=sys.stderr)
                self.next_check = time.monotonic() + self.interval
            except Exception as exc:
                if self.error:
                    raise RuntimeError(self.error) from exc
                ui_print(
                    f"[yellow]基准复查暂时失败：{type(exc).__name__}: {exc}；稍后重试。[/yellow]"
                    if RICH_CONSOLE
                    else f"\n基准复查暂时失败：{type(exc).__name__}: {exc}；稍后重试。"
                )
                self.next_check = time.monotonic() + min(self.interval, 60.0)


async def probe_once(
    index: int,
    target_ip: str,
    endpoint: Endpoint,
    own_ip: ipaddress.IPv4Address,
    ssl_context: ssl.SSLContext,
    timeout: float,
    connect_timeout: float,
    test_host: str,
) -> ProbeResult:
    try:
        response = await request_trace(
            target_ip,
            endpoint,
            ssl_context,
            timeout,
            connect_timeout,
            test_host,
        )
        trace_ip = ipaddress.ip_address(response.trace["ip"])
        match = trace_ip != own_ip
        record = None
        if match:
            record = {
                "target_index": index,
                "target_ip": target_ip,
                "port": endpoint.port,
                "tls_enabled": endpoint.tls,
                "scheme": endpoint.scheme,
                "test_host": test_host,
                "baseline_egress_ip": str(own_ip),
                "trace_ip": str(trace_ip),
                "trace_ip_type": f"IPv{trace_ip.version}",
                "http_status": response.status,
                "timing_ms": {
                    "tcp": response.tcp_ms,
                    "connect": response.connect_ms,
                    "ttfb": response.ttfb_ms,
                    "total": response.total_ms,
                },
                "trace": response.trace,
                "response_headers": response.headers,
                "download_speed_mbps": None,
                "download_error": None,
                "scanned_at": utc_now(),
            }
        return ProbeResult(index, target_ip, endpoint, True, match, record)
    except Exception as exc:
        return ProbeResult(
            index=index,
            target_ip=target_ip,
            endpoint=endpoint,
            ok=False,
            error=f"{type(exc).__name__}: {exc}",
        )


async def download_speed_once(
    target_ip: str,
    endpoint: Endpoint,
    ssl_context: ssl.SSLContext,
    speed_host: str,
    speed_path: str,
    duration: float,
    connect_timeout: float,
) -> float:
    writer: Optional[asyncio.StreamWriter] = None
    try:
        reader, writer, _ = await asyncio.wait_for(
            open_target(
                target_ip,
                endpoint,
                ssl_context,
                speed_host,
                connect_timeout,
                min(3.0, connect_timeout),
            ),
            timeout=connect_timeout,
        )
        request = (
            f"GET {speed_path} HTTP/1.1\r\n"
            f"Host: {host_header(speed_host, endpoint)}\r\n"
            f"User-Agent: {USER_AGENT}\r\n"
            "Accept: */*\r\n"
            "Accept-Encoding: identity\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii")
        writer.write(request)
        await writer.drain()
        header_blob = await asyncio.wait_for(
            reader.readuntil(b"\r\n\r\n"), timeout=connect_timeout
        )
        status_line = header_blob.split(b"\r\n", 1)[0].decode(
            "ascii", errors="replace"
        )
        status_parts = status_line.split(" ", 2)
        if len(status_parts) < 2 or status_parts[1] != "200":
            raise ValueError(f"下载接口状态异常: {status_line}")

        received = 0
        started = time.perf_counter()
        deadline = started + duration
        while True:
            remaining = deadline - time.perf_counter()
            if remaining <= 0:
                break
            try:
                chunk = await asyncio.wait_for(
                    reader.read(64 * 1024), timeout=remaining
                )
            except asyncio.TimeoutError:
                break
            if not chunk:
                break
            received += len(chunk)
        elapsed = max(time.perf_counter() - started, 0.001)
        if received == 0:
            raise ValueError("下载接口没有返回内容")
        return round(received / 1_000_000 / elapsed, 3)
    finally:
        if writer is not None:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()


def record_to_csv(record: dict) -> dict:
    trace = record["trace"]
    timing = record["timing_ms"]
    speed = record.get("download_speed_mbps")
    return {
        "候选IP": record["target_ip"],
        "端口": record["port"],
        "TLS开关": "开启" if record["tls_enabled"] else "关闭",
        "Cloudflare数据中心": trace.get("colo", ""),
        "出口国家代码": trace.get("loc", ""),
        "网络延迟(ms)": timing.get("tcp", ""),
        "下载速度(MB/s)": "" if speed is None else speed,
        "出站IP": record["trace_ip"],
        "出站IP类型": record["trace_ip_type"],
        "访问协议": trace.get("visit_scheme", record.get("scheme", "")),
        "HTTP版本": trace.get("http", ""),
        "TLS版本": trace.get("tls", ""),
        "Host": trace.get("h", record.get("test_host", "")),
        "扫描时间": record["scanned_at"],
    }


def sort_csv_by_download_speed(path: Path) -> int:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))

    def number(value: str, default: float) -> float:
        try:
            return float(value)
        except (TypeError, ValueError):
            return default

    def sort_key(row: dict):
        speed_text = str(row.get("下载速度(MB/s)", "")).strip()
        latency = number(str(row.get("网络延迟(ms)", "")), float("inf"))
        if speed_text:
            return 0, -number(speed_text, 0.0), latency
        return 1, 0.0, latency

    rows.sort(key=sort_key)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_FIELDS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    temporary.replace(path)
    return len(rows)


def write_records_csv(path: Path, records: List[dict]) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_FIELDS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(record_to_csv(record) for record in records)
    temporary.replace(path)


def load_records_from_csv(path: Path) -> List[dict]:
    if not path.exists() or path.stat().st_size == 0:
        raise ValueError("续扫 CSV 不存在或为空")
    records: List[dict] = []
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if tuple(reader.fieldnames or ()) != CSV_FIELDS:
            raise ValueError("续扫 CSV 表头与当前版本不一致")
        for line_number, row in enumerate(reader, start=2):
            try:
                target_ip = row["候选IP"].strip()
                port = int(row["端口"])
                tls_enabled = row["TLS开关"] == "开启"
                speed_text = row["下载速度(MB/s)"].strip()
                if not target_ip or not 1 <= port <= 65535:
                    raise ValueError("候选 IP 或端口无效")
                records.append(
                    {
                        "target_ip": target_ip,
                        "port": port,
                        "tls_enabled": tls_enabled,
                        "scheme": row["访问协议"],
                        "test_host": row["Host"],
                        "trace_ip": row["出站IP"],
                        "trace_ip_type": row["出站IP类型"],
                        "timing_ms": {"tcp": float(row["网络延迟(ms)"] or 0)},
                        "trace": {
                            "ip": row["出站IP"],
                            "colo": row["Cloudflare数据中心"],
                            "loc": row["出口国家代码"],
                            "visit_scheme": row["访问协议"],
                            "http": row["HTTP版本"],
                            "tls": row["TLS版本"],
                            "h": row["Host"],
                        },
                        "download_speed_mbps": float(speed_text) if speed_text else None,
                        "download_error": None,
                        "scanned_at": row["扫描时间"],
                    }
                )
            except (KeyError, TypeError, ValueError) as exc:
                raise ValueError(f"续扫 CSV 第 {line_number} 行无效: {exc}") from exc
    return records


def record_unique_key(record: dict) -> Tuple[str, int, bool]:
    return (
        str(record.get("target_ip", "")),
        int(record.get("port", 0)),
        bool(record.get("tls_enabled", False)),
    )


def read_checkpoint_file(path: Path) -> Optional[dict]:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        print(f"无法读取检查点：{exc}", file=sys.stderr)
        return None


def load_checkpoint_state(path: Path, fingerprint: str) -> Optional[dict]:
    state = read_checkpoint_file(path)
    if state is None:
        return None
    try:
        if state.get("scan_sha256") != fingerprint:
            print("端口、协议或 Cloudflare 网段已变化，将从头扫描。", file=sys.stderr)
            return None
        return state
    except (ValueError, TypeError) as exc:
        print(f"检查点内容无效，将从头扫描：{exc}", file=sys.stderr)
        return None


def build_scan_config(args: SimpleNamespace) -> dict:
    return {
        "ports": args.ports or (
            ",".join(str(port) for port in args.port) if args.port else "443"
        ),
        "host": args.host,
        "tls": args.tls,
        "auto_protocol": args.auto_protocol,
        "concurrency": args.concurrency,
        "timeout": args.timeout,
        "connect_timeout": args.connect_timeout,
        "speedtest": args.speedtest,
        "speed_concurrency": args.speed_concurrency,
        "speed_url": args.speed_url,
        "speed_duration": args.speed_duration,
        "speed_timeout": args.speed_timeout,
    }


def apply_saved_scan_config(args: SimpleNamespace, config: dict) -> None:
    args.port = None
    args.ports = str(config.get("ports") or "443")
    args.host = normalize_test_host(str(config.get("host") or TRACE_HOST))
    args.tls = bool(config.get("tls", True))
    args.auto_protocol = bool(config.get("auto_protocol", True))
    args.concurrency = max(1, int(config.get("concurrency", 100)))
    args.timeout = max(0.1, float(config.get("timeout", 3.0)))
    args.connect_timeout = max(0.1, float(config.get("connect_timeout", 1.2)))
    args.speedtest = bool(config.get("speedtest", False))
    args.speed_concurrency = max(1, int(config.get("speed_concurrency", 3)))
    args.speed_url = str(config.get("speed_url") or DEFAULT_SPEED_URL)
    args.speed_host, args.speed_path = parse_speed_url(args.speed_url)
    args.speed_url = f"https://{args.speed_host}{args.speed_path}"
    args.speed_duration = max(0.1, float(config.get("speed_duration", 10.0)))
    args.speed_timeout = max(0.1, float(config.get("speed_timeout", 15.0)))


def show_resume_config(state: dict, config: dict) -> None:
    next_index = int(state.get("next_index", 0))
    output_file = str(state.get("output_file", ""))
    speed_text = (
        f"开启, 并发 {config.get('speed_concurrency', 3)}, "
        f"{config.get('speed_url', DEFAULT_SPEED_URL)}"
        if config.get("speedtest", False)
        else "关闭"
    )
    if RICH_CONSOLE is not None:
        from rich import box
        from rich.table import Table

        table = Table(title="检测到未完成的全量扫描", box=box.ASCII)
        table.add_column("项目", style="bold")
        table.add_column("上次配置")
        table.add_row("已完成序号", f"{next_index:,}")
        table.add_row(
            "当前阶段",
            "等待统一测速" if state.get("phase") == "speedtest" else "扫描中",
        )
        table.add_row("端口", str(config.get("ports", "443")))
        table.add_row("Host", str(config.get("host", TRACE_HOST)))
        table.add_row("扫描并发", str(config.get("concurrency", 100)))
        table.add_row("单项超时", f"{config.get('timeout', 3.0)} 秒")
        table.add_row("TCP 超时", f"{config.get('connect_timeout', 1.2)} 秒")
        table.add_row("下载测速", speed_text)
        table.add_row("结果文件", output_file)
        RICH_CONSOLE.print(table)
    else:
        print("\n检测到未完成的全量扫描:")
        print(f"  已完成序号: {next_index:,}")
        print(
            "  当前阶段: "
            + ("等待统一测速" if state.get("phase") == "speedtest" else "扫描中")
        )
        print(f"  端口: {config.get('ports', '443')}")
        print(f"  Host: {config.get('host', TRACE_HOST)}")
        print(f"  扫描并发: {config.get('concurrency', 100)}")
        print(f"  单项超时: {config.get('timeout', 3.0)} 秒")
        print(f"  TCP 超时: {config.get('connect_timeout', 1.2)} 秒")
        print(f"  下载测速: {speed_text}")
        print(f"  结果文件: {output_file}")


def save_checkpoint(
    path: Path,
    fingerprint: str,
    next_index: int,
    completed: bool,
    output_path: Optional[Path] = None,
    scan_config: Optional[dict] = None,
    phase: str = "scan",
) -> None:
    state = {
        "scan_sha256": fingerprint,
        "next_index": next_index,
        "completed": completed,
        "phase": phase,
        "updated_at": utc_now(),
    }
    if output_path is not None:
        state["output_file"] = str(output_path.resolve())
    if scan_config is not None:
        state["scan_config"] = scan_config
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(state, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    temporary.replace(path)


def create_scan_progress(endpoint_count: int):
    if RICH_CONSOLE is None:
        return None
    from rich.progress import (
        Progress,
        ProgressColumn,
        SpinnerColumn,
        Task,
        TaskProgressColumn,
        TextColumn,
        TimeRemainingColumn,
    )
    from rich.text import Text

    class CountsColumn(ProgressColumn):
        def render(self, task: Task) -> Text:
            total = int(task.total or 0)
            return Text(f"{int(task.completed):,}/{total:,}", style="cyan")

    class AsciiBarColumn(ProgressColumn):
        def render(self, task: Task) -> Text:
            width = 20
            ratio = min(max(float(task.percentage) / 100.0, 0.0), 1.0)
            complete = int(ratio * width)
            return Text(
                "[" + "#" * complete + "-" * (width - complete) + "]",
                style="cyan" if ratio < 1.0 else "green",
            )

    class ScanSpeedColumn(ProgressColumn):
        def render(self, task: Task) -> Text:
            item_speed = float(task.speed or 0.0)
            ip_speed = item_speed / max(endpoint_count, 1)
            return Text(f"{ip_speed:,.1f} IP/s", style="bold green")

    class StatsColumn(ProgressColumn):
        def render(self, task: Task) -> Text:
            success = int(task.fields.get("success", 0))
            failed = int(task.fields.get("failed", 0))
            matched = int(task.fields.get("matched", 0))
            text = Text()
            text.append(f"成 {success:,}", style="green")
            text.append(f" 败 {failed:,}", style="red")
            text.append(f" 候 {matched:,}", style="bold yellow")
            return text

    return Progress(
        SpinnerColumn("line", style="cyan"),
        TextColumn("[bold cyan]{task.description}"),
        AsciiBarColumn(),
        TaskProgressColumn(),
        CountsColumn(),
        ScanSpeedColumn(),
        StatsColumn(),
        TextColumn("剩"),
        TimeRemainingColumn(),
        console=RICH_CONSOLE,
        refresh_per_second=8,
        expand=True,
    )


def create_speed_progress():
    if RICH_CONSOLE is None:
        return None
    from rich.progress import (
        Progress,
        ProgressColumn,
        SpinnerColumn,
        Task,
        TaskProgressColumn,
        TextColumn,
        TimeRemainingColumn,
    )
    from rich.text import Text

    class AsciiBarColumn(ProgressColumn):
        def render(self, task: Task) -> Text:
            width = 20
            ratio = min(max(float(task.percentage) / 100.0, 0.0), 1.0)
            complete = int(ratio * width)
            return Text(
                "[" + "#" * complete + "-" * (width - complete) + "]",
                style="cyan" if ratio < 1.0 else "green",
            )

    class CountsColumn(ProgressColumn):
        def render(self, task: Task) -> Text:
            return Text(
                f"{int(task.completed):,}/{int(task.total or 0):,}", style="cyan"
            )

    class StatsColumn(ProgressColumn):
        def render(self, task: Task) -> Text:
            success = int(task.fields.get("success", 0))
            failed = int(task.fields.get("failed", 0))
            text = Text()
            text.append(f"成 {success:,}", style="green")
            text.append(f" 败 {failed:,}", style="red")
            return text

    return Progress(
        SpinnerColumn("line", style="cyan"),
        TextColumn("[bold cyan]{task.description}"),
        AsciiBarColumn(),
        TaskProgressColumn(),
        CountsColumn(),
        StatsColumn(),
        TextColumn("剩"),
        TimeRemainingColumn(),
        console=RICH_CONSOLE,
        refresh_per_second=8,
        expand=True,
    )


async def run_speed_phase(
    records: List[dict], args: SimpleNamespace, ssl_context: ssl.SSLContext
) -> None:
    if not records:
        ui_print(
            "[yellow]扫描没有发现特殊线路候选, 跳过下载测速.[/yellow]"
            if RICH_CONSOLE
            else "扫描没有发现特殊线路候选, 跳过下载测速."
        )
        return

    ui_print(
        f"[bold cyan]扫描完成, 开始统一测速: {len(records)} 个目标, "
        f"并发 {args.speed_concurrency}[/bold cyan]"
        if RICH_CONSOLE
        else f"扫描完成, 开始统一测速: {len(records)} 个目标, 并发 {args.speed_concurrency}"
    )
    queue: asyncio.Queue[Optional[dict]] = asyncio.Queue()
    for record in records:
        await queue.put(record)
    worker_count = min(args.speed_concurrency, len(records))
    for _ in range(worker_count):
        await queue.put(None)

    progress = create_speed_progress()
    task_id = None
    if progress is not None:
        progress.start()
        task_id = progress.add_task(
            "测速中", total=len(records), completed=0, success=0, failed=0
        )
    completed = success = failed = 0

    async def worker() -> None:
        nonlocal completed, success, failed
        while True:
            record = await queue.get()
            try:
                if record is None:
                    return
                target_ip = str(record["target_ip"])
                endpoint = Endpoint(int(record["port"]), bool(record["tls_enabled"]))
                start_message = (
                    f"测速开始 {target_ip}:{endpoint.port}, 持续 {args.speed_duration:g} 秒"
                )
                if progress is not None:
                    progress.console.print(f"[cyan]{start_message}[/cyan]")
                else:
                    print(start_message)
                try:
                    speed = await download_speed_once(
                        target_ip,
                        endpoint,
                        ssl_context,
                        args.speed_host,
                        args.speed_path,
                        args.speed_duration,
                        args.speed_timeout,
                    )
                    record["download_speed_mbps"] = speed
                    success += 1
                    finish_message = (
                        f"测速完成 {target_ip}:{endpoint.port}, {speed:.3f} MB/s"
                    )
                    if progress is not None:
                        progress.console.print(f"[green]{finish_message}[/green]")
                    else:
                        print(finish_message)
                except Exception as exc:
                    record["download_error"] = f"{type(exc).__name__}: {exc}"
                    failed += 1
                    fail_message = (
                        f"测速失败 {target_ip}:{endpoint.port}, {record['download_error']}"
                    )
                    if progress is not None:
                        progress.console.print(f"[yellow]{fail_message}[/yellow]")
                    else:
                        print(fail_message)
                completed += 1
                if progress is not None and task_id is not None:
                    progress.update(
                        task_id,
                        completed=completed,
                        success=success,
                        failed=failed,
                    )
            finally:
                queue.task_done()

    workers = [asyncio.create_task(worker()) for _ in range(worker_count)]
    await queue.join()
    await asyncio.gather(*workers)
    if progress is not None:
        progress.stop()


async def run_scan(
    args: SimpleNamespace,
    networks: List[ipaddress.IPv4Network],
    endpoints: List[Endpoint],
    sampled_ip_indices: Optional[List[int]],
    own_ip: ipaddress.IPv4Address,
    ssl_context: ssl.SSLContext,
    baseline_guard: BaselineGuard,
    start_index: int,
    fingerprint: str,
) -> None:
    target_queue: asyncio.Queue[Optional[Tuple[int, str, Endpoint]]] = asyncio.Queue(
        maxsize=args.concurrency * 4
    )
    result_queue: asyncio.Queue[Optional[ProbeResult]] = asyncio.Queue(
        maxsize=args.concurrency * 4
    )
    output_path = Path(args.output)
    checkpoint_path = Path(args.checkpoint)
    selected_ip_count = (
        len(sampled_ip_indices)
        if sampled_ip_indices is not None
        else sum(item.num_addresses for item in networks)
    )
    total_units = selected_ip_count * len(endpoints)
    checkpoint_enabled = args.scan_mode == "full"
    append_output = checkpoint_enabled and args.resume_scan and start_index > 0
    resumed_records: List[dict] = []
    if append_output:
        try:
            resumed_records = load_records_from_csv(output_path)
        except ValueError as exc:
            raise RuntimeError(f"无法继续全量扫描: {exc}") from exc

    async def producer() -> None:
        for item in iter_scan_targets(
            networks,
            endpoints,
            start_index,
            args.limit,
            sampled_ip_indices,
        ):
            if baseline_guard.abort_event.is_set():
                break
            await target_queue.put(item)
        for _ in range(args.concurrency):
            await target_queue.put(None)

    async def worker() -> None:
        while True:
            item = await target_queue.get()
            try:
                if item is None:
                    break
                if baseline_guard.abort_event.is_set():
                    continue
                index, target_ip, endpoint = item
                try:
                    await baseline_guard.maybe_check()
                except RuntimeError:
                    continue
                if baseline_guard.abort_event.is_set():
                    continue
                result = await probe_once(
                    index,
                    target_ip,
                    endpoint,
                    own_ip,
                    ssl_context,
                    args.timeout,
                    args.connect_timeout,
                    args.host,
                )
                await result_queue.put(result)
            finally:
                target_queue.task_done()
        await result_queue.put(None)

    async def writer_task() -> List[dict]:
        next_index = start_index
        pending_done: Set[int] = set()
        finished_workers = 0
        scanned = succeeded = failed = matched = 0
        last_report = last_checkpoint = time.monotonic()
        started_at = time.monotonic()
        matched_records: List[dict] = list(resumed_records)
        existing_record_keys = {
            record_unique_key(record) for record in matched_records
        }
        progress = create_scan_progress(len(endpoints))
        progress_task_id = None
        if progress is not None:
            progress.start()
            progress_task_id = progress.add_task(
                "移动特殊线路扫描",
                total=total_units,
                completed=start_index,
                success=0,
                failed=0,
                matched=0,
            )

        output_path.parent.mkdir(parents=True, exist_ok=True)
        if checkpoint_enabled:
            checkpoint_path.parent.mkdir(parents=True, exist_ok=True)

        file_mode = "a" if append_output else "w"
        csv_encoding = "utf-8" if append_output else "utf-8-sig"
        with output_path.open(file_mode, encoding=csv_encoding, newline="") as csv_handle:
            csv_writer = csv.DictWriter(
                csv_handle, fieldnames=CSV_FIELDS, extrasaction="ignore"
            )
            if not append_output:
                csv_writer.writeheader()
                csv_handle.flush()
            try:
                while finished_workers < args.concurrency:
                    result = await result_queue.get()
                    try:
                        if result is None:
                            finished_workers += 1
                            continue
                        scanned += 1
                        pending_done.add(result.index)
                        while next_index in pending_done:
                            pending_done.remove(next_index)
                            next_index += 1

                        if result.ok:
                            succeeded += 1
                        else:
                            failed += 1

                        if result.match and result.record:
                            result_key = record_unique_key(result.record)
                            if result_key not in existing_record_keys:
                                matched += 1
                                existing_record_keys.add(result_key)
                                matched_records.append(result.record)
                                row = record_to_csv(result.record)
                                csv_writer.writerow(row)
                                csv_handle.flush()
                                message = (
                                    f"[bold yellow]发现候选[/bold yellow] "
                                    f"[cyan]{result.target_ip}:{result.endpoint.port}[/cyan] "
                                    f"TLS={'开' if result.endpoint.tls else '关'} -> "
                                    f"[bold]{result.record['trace_ip']}[/bold] "
                                    f"colo={row['Cloudflare数据中心']} "
                                    f"loc={row['出口国家代码']}"
                                )
                                if progress is not None:
                                    progress.console.print(message)
                                else:
                                    print(message.replace("[bold yellow]", "").replace("[/bold yellow]", "").replace("[cyan]", "").replace("[/cyan]", "").replace("[bold]", "").replace("[/bold]", ""), flush=True)

                        if progress is not None and progress_task_id is not None:
                            progress.update(
                                progress_task_id,
                                completed=min(start_index + scanned, total_units),
                                success=succeeded,
                                failed=failed,
                                matched=matched,
                            )

                        now = time.monotonic()
                        if progress is None and now - last_report >= args.progress_interval:
                            elapsed = max(now - started_at, 0.001)
                            print(
                                f"\r进度 {next_index}/{total_units} "
                                f"({next_index / total_units * 100:.2f}%)，"
                                f"本次 {scanned}，成功 {succeeded}，失败 {failed}，"
                                f"候选 {matched}，{scanned / elapsed:.1f} 项/s",
                                end="",
                                file=sys.stderr,
                                flush=True,
                            )
                            last_report = now
                        if (
                            checkpoint_enabled
                            and now - last_checkpoint >= args.checkpoint_interval
                        ):
                            save_checkpoint(
                                checkpoint_path,
                                fingerprint,
                                next_index,
                                False,
                                output_path,
                                build_scan_config(args),
                            )
                            last_checkpoint = now
                    finally:
                        result_queue.task_done()
            finally:
                csv_handle.flush()

        completed = (
            args.limit is None
            and next_index >= total_units
            and not args.speedtest
        )
        if checkpoint_enabled:
            save_checkpoint(
                checkpoint_path,
                fingerprint,
                next_index,
                completed,
                output_path,
                build_scan_config(args),
                "complete" if completed else ("speedtest" if next_index >= total_units else "scan"),
            )
        elapsed = max(time.monotonic() - started_at, 0.001)
        if progress is not None:
            progress.stop()
            from rich import box
            from rich.panel import Panel

            RICH_CONSOLE.print(
                Panel.fit(
                    f"[bold green]扫描阶段结束[/bold green]\n"
                    f"扫描 [cyan]{scanned:,}[/cyan] 项  "
                    f"成功 [green]{succeeded:,}[/green]  "
                    f"失败 [red]{failed:,}[/red]  "
                    f"候选 [bold yellow]{matched:,}[/bold yellow]\n"
                    f"耗时 {elapsed:.1f} 秒  平均 {scanned / elapsed:,.1f} 项/s",
                    border_style="green",
                    box=box.ASCII,
                )
            )
        else:
            print(
                f"\n完成：扫描 {scanned}，成功 {succeeded}，失败 {failed}，"
                f"候选 {matched}，耗时 {elapsed:.1f} 秒，下一序号 {next_index}。",
                file=sys.stderr,
            )
        return matched_records

    if append_output and start_index >= total_units:
        matched_records = load_records_from_csv(output_path)
    else:
        producer_task = asyncio.create_task(producer())
        workers = [asyncio.create_task(worker()) for _ in range(args.concurrency)]
        output_task = asyncio.create_task(writer_task())
        await producer_task
        await target_queue.join()
        await asyncio.gather(*workers)
        await result_queue.join()
        matched_records = await output_task
    if baseline_guard.error:
        raise RuntimeError(
            baseline_guard.error
            + (
                "；全量扫描已停止并保存检查点，请重新确认基准 IP。"
                if args.scan_mode == "full"
                else "；随机扫描已停止，请重新确认基准 IP 后重新扫描。"
            )
        )
    if args.speedtest:
        await run_speed_phase(matched_records, args, ssl_context)
        write_records_csv(output_path, matched_records)
        sorted_count = sort_csv_by_download_speed(output_path)
        ui_print(
            f"[green]测速结束, CSV 已按下载速度从高到低排序, "
            f"共 {sorted_count} 条结果.[/green]"
            if RICH_CONSOLE
            else f"测速结束, CSV 已按下载速度从高到低排序, 共 {sorted_count} 条结果."
        )
        if checkpoint_enabled:
            save_checkpoint(
                checkpoint_path,
                fingerprint,
                total_units,
                True,
                output_path,
                build_scan_config(args),
                "complete",
            )
    if not matched_records:
        if args.scan_mode == "random":
            reminder = "本次随机扫描未发现特殊线路 Cloudflare IP, 建议增大随机 IP 数量再次扫描或进行全量扫描."
        else:
            reminder = (
                "暂未发现当前环境下的特殊线路 Cloudflare IP, "
                "如需进一步确认, 可以选择降低并发再次扫描."
            )
        ui_print(
            f"[yellow]{reminder}[/yellow]" if RICH_CONSOLE else reminder
        )


async def async_main(args: SimpleNamespace) -> None:
    endpoints = parse_endpoints(args)
    if RICH_CONSOLE is not None:
        with RICH_CONSOLE.status(
            "[bold cyan]正在获取 Cloudflare 官方 IPv4 网段...[/bold cyan]",
            spinner="dots",
        ):
            networks = await asyncio.to_thread(
                fetch_cloudflare_networks, args.ranges_url, 15
            )
    else:
        print(f"正在从 {args.ranges_url} 获取 Cloudflare IPv4 网段...", file=sys.stderr)
        networks = await asyncio.to_thread(
            fetch_cloudflare_networks, args.ranges_url, 15
        )
    address_total = sum(item.num_addresses for item in networks)
    while True:
        try:
            if RICH_CONSOLE is not None:
                with RICH_CONSOLE.status(
                    f"[bold cyan]正在验证测试 Host: {args.host}...[/bold cyan]",
                    spinner="line",
                ):
                    host_addresses = await validate_cloudflare_host(args.host, networks)
            else:
                host_addresses = await validate_cloudflare_host(args.host, networks)
            break
        except Exception as exc:
            if not args.interactive:
                raise RuntimeError(f"测试 Host 验证失败: {exc}") from exc
            ui_print(
                f"[bold red]测试 Host 验证失败: {exc}[/bold red]"
                if RICH_CONSOLE
                else f"测试 Host 验证失败: {exc}"
            )
            while True:
                try:
                    args.host = normalize_test_host(
                        prompt_text(
                            "请重新输入托管在 Cloudflare 的测试 Host",
                            TRACE_HOST,
                        )
                    )
                    break
                except ValueError as host_exc:
                    ui_print(
                        f"[red]Host 无效: {host_exc}[/red]"
                        if RICH_CONSOLE
                        else f"Host 无效: {host_exc}"
                    )
    sampled_ip_indices: Optional[List[int]] = None
    if args.speedtest:
        while True:
            try:
                if RICH_CONSOLE is not None:
                    with RICH_CONSOLE.status(
                        f"[bold cyan]正在验证测速域名: {args.speed_host}...[/bold cyan]",
                        spinner="line",
                    ):
                        await validate_cloudflare_host(args.speed_host, networks)
                else:
                    await validate_cloudflare_host(args.speed_host, networks)
                break
            except Exception as exc:
                if args.run_mode == "onekey" or args.resume_scan:
                    raise RuntimeError(f"测速域名验证失败: {exc}") from exc
                ui_print(
                    f"[bold red]测速域名验证失败: {exc}[/bold red]"
                    if RICH_CONSOLE
                    else f"测速域名验证失败: {exc}"
                )
                while True:
                    try:
                        args.speed_url = prompt_text(
                            "请重新输入托管在 Cloudflare 的 HTTPS 测速链接",
                            DEFAULT_SPEED_URL,
                        )
                        args.speed_host, args.speed_path = parse_speed_url(
                            args.speed_url
                        )
                        args.speed_url = (
                            f"https://{args.speed_host}{args.speed_path}"
                        )
                        break
                    except ValueError as url_exc:
                        ui_print(
                            f"[red]测速链接无效: {url_exc}[/red]"
                            if RICH_CONSOLE
                            else f"测速链接无效: {url_exc}"
                        )
    if args.scan_mode == "random":
        sampled_ip_indices = await asyncio.to_thread(
            load_or_create_sample,
            networks,
            args.sample_size,
            Path(args.sample_file),
            args.reuse_sample,
        )
    selected_ip_count = (
        len(sampled_ip_indices) if sampled_ip_indices is not None else address_total
    )
    total_units = selected_ip_count * len(endpoints)
    fingerprint = scan_fingerprint(
        networks, endpoints, sampled_ip_indices, args.host
    )
    start_index = 0
    if args.scan_mode == "full":
        checkpoint_path = Path(args.checkpoint)
        checkpoint_state = None
        if args.resume_scan and args.resume_state:
            checkpoint_state = args.resume_state
        elif not args.skip_resume_checkpoint:
            checkpoint_state = load_checkpoint_state(checkpoint_path, fingerprint)
        if args.resume_scan and checkpoint_state:
            if checkpoint_state.get("scan_sha256") != fingerprint:
                ui_print(
                    "[yellow]Cloudflare 网段或恢复配置已变化, 无法续扫, 将开始新的全量扫描.[/yellow]"
                    if RICH_CONSOLE
                    else "Cloudflare 网段或恢复配置已变化, 无法续扫, 将开始新的全量扫描."
                )
                args.resume_scan = False
                checkpoint_state = None
        if checkpoint_state and checkpoint_state.get("phase") == "speedtest":
            saved_output_text = str(checkpoint_state.get("output_file", "")).strip()
            saved_output = Path(saved_output_text) if saved_output_text else None
            if saved_output and saved_output.exists():
                args.output = str(saved_output)
                args.resume_scan = True
                start_index = total_units
        elif checkpoint_state and not checkpoint_state.get("completed", False):
            saved_index = max(0, int(checkpoint_state.get("next_index", 0)))
            saved_output_text = str(checkpoint_state.get("output_file", "")).strip()
            saved_output = Path(saved_output_text) if saved_output_text else None
            can_resume = (
                0 < saved_index < total_units
                and saved_output is not None
                and saved_output.exists()
            )
            should_resume = args.resume_scan or (
                can_resume
                and prompt_yes_no(
                    f"检测到未完成的全量扫描 ({saved_index}/{total_units}), 是否断点续扫",
                    True,
                )
            )
            if can_resume and should_resume:
                start_index = saved_index
                args.output = str(saved_output)
                args.resume_scan = True
                ui_print(
                    f"[green]将从序号 {start_index} 继续, 结果追加到 {args.output}[/green]"
                    if RICH_CONSOLE
                    else f"将从序号 {start_index} 继续, 结果追加到 {args.output}"
                )
            elif args.resume_scan:
                args.resume_scan = False
        if not args.resume_scan:
            args.output = create_timestamped_output_filename()
    else:
        args.output = create_timestamped_output_filename()
        args.start_index = 0
    if RICH_CONSOLE is not None:
        from rich import box
        from rich.table import Table

        config_table = Table(
            title="扫描配置",
            header_style="bold cyan",
            border_style="blue",
            show_lines=False,
            box=box.ASCII,
        )
        config_table.add_column("项目", style="bold")
        config_table.add_column("配置")
        config_table.add_row(
            "扫描范围",
            "随机抽取" if sampled_ip_indices is not None else "全部 Cloudflare IPv4",
        )
        config_table.add_row("官方网段", f"{len(networks):,} 个 / {address_total:,} 个 IPv4")
        config_table.add_row("本次 IP", f"{selected_ip_count:,}")
        config_table.add_row("端点", ", ".join(item.key for item in endpoints))
        config_table.add_row(
            "测试 Host",
            f"{args.host} ({', '.join(str(address) for address in host_addresses)})",
        )
        config_table.add_row("扫描任务", f"{total_units:,} 项")
        config_table.add_row("探测并发", str(args.concurrency))
        config_table.add_row("TCP 连接超时", f"{args.connect_timeout:g} 秒")
        config_table.add_row("单项超时", f"{args.timeout:g} 秒")
        config_table.add_row(
            "下载测速",
            f"开启 / 并发 {args.speed_concurrency} / {args.speed_duration:g} 秒 / {args.speed_url}"
            if args.speedtest
            else "关闭",
        )
        config_table.add_row("CSV 输出", args.output)
        RICH_CONSOLE.print(config_table)
    else:
        print(
            f"获得 {len(networks)} 个网段、{address_total} 个 IPv4；"
            f"本次选择 {selected_ip_count} 个 IP；端点："
            f"{', '.join(item.key for item in endpoints)}；测试 Host：{args.host}；"
            f"共 {total_units} 个扫描项。",
            file=sys.stderr,
        )

    ssl_context = build_ssl_context(args.insecure)
    if RICH_CONSOLE is not None:
        with RICH_CONSOLE.status(
            "[bold cyan]正在通过 Cloudflare 与国内接口交叉验证出口 IP...[/bold cyan]",
            spinner="dots",
        ):
            cloudflare_result, domestic_query = await asyncio.gather(
                get_cloudflare_egress_ipv4(
                    ssl_context, args.baseline_timeout, args.connect_timeout
                ),
                asyncio.to_thread(query_domestic_egress_ipv4s, args.baseline_timeout),
            )
    else:
        cloudflare_result, domestic_query = await asyncio.gather(
            get_cloudflare_egress_ipv4(
                ssl_context, args.baseline_timeout, args.connect_timeout
            ),
            asyncio.to_thread(query_domestic_egress_ipv4s, args.baseline_timeout),
        )
    cloudflare_ip, baseline_target = cloudflare_result
    domestic_results, domestic_errors = domestic_query
    own_ip = select_baseline_ip(
        cloudflare_ip,
        domestic_results,
        domestic_errors,
        args.interactive,
        args.baseline_ip,
    )
    ui_print(
        f"[bold green]已确认基准公网 IPv4：{own_ip}[/bold green]  "
        f"[dim]Cloudflare 目标 {baseline_target}:443[/dim]"
        if RICH_CONSOLE
        else f"已确认基准公网 IPv4：{own_ip}；Cloudflare 目标 {baseline_target}:443"
    )
    baseline_guard = BaselineGuard(
        cloudflare_ip,
        domestic_results,
        ssl_context,
        args.baseline_timeout,
        args.connect_timeout,
        args.baseline_recheck_interval,
    )
    if args.baseline_recheck_interval > 0:
        ui_print(
            f"[dim]基准保护：每 {args.baseline_recheck_interval:g} 秒复查一次出口 IP。[/dim]"
            if RICH_CONSOLE
            else f"扫描期间每 {args.baseline_recheck_interval:g} 秒复查一次基准出口。"
        )

    if start_index >= total_units and not args.resume_scan:
        print("检查点显示全部 IP/端口组合已经扫描完成。", file=sys.stderr)
        return
    if RICH_CONSOLE is None:
        print(
            f"从序号 {start_index} 开始，并发 {args.concurrency}，"
            f"TCP 超时 {args.connect_timeout:g} 秒，trace 总超时 {args.timeout:g} 秒，"
            f"下载测速={'开启' if args.speedtest else '关闭'}。",
            file=sys.stderr,
        )
    await run_scan(
        args,
        networks,
        endpoints,
        sampled_ip_indices,
        own_ip,
        ssl_context,
        baseline_guard,
        start_index,
        fingerprint,
    )




def create_timestamped_output_filename() -> str:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base = SCRIPT_DIR / f"cmcc_cf_special_route_{timestamp}.csv"
    if not base.exists():
        return str(base)
    counter = 1
    while True:
        candidate = base.with_name(f"{base.stem}_{counter}{base.suffix}")
        if not candidate.exists():
            return str(candidate)
        counter += 1


def create_default_config() -> SimpleNamespace:
    return SimpleNamespace(
        run_mode="custom",
        port=None,
        ports=None,
        host=TRACE_HOST,
        scan_mode="random",
        sample_size=10000,
        sample_file=str(DATA_DIR / "random_sample.json"),
        reuse_sample=False,
        resume_scan=False,
        resume_state=None,
        skip_resume_checkpoint=False,
        tls=True,
        auto_protocol=True,
        concurrency=100,
        timeout=3.0,
        connect_timeout=1.2,
        baseline_timeout=5.0,
        baseline_ip=None,
        baseline_recheck_interval=300.0,
        speedtest=False,
        speed_concurrency=3,
        speed_url=DEFAULT_SPEED_URL,
        speed_host=DOWNLOAD_HOST,
        speed_path=DOWNLOAD_PATH,
        speed_duration=10.0,
        speed_timeout=15.0,
        output=create_timestamped_output_filename(),
        checkpoint=str(DATA_DIR / "checkpoint.json"),
        limit=None,
        start_index=None,
        insecure=True,
        ranges_url=CLOUDFLARE_IPV4_URL,
        progress_interval=2.0,
        checkpoint_interval=5.0,
        interactive=True,
    )


def pause_before_exit(interactive: bool) -> None:
    if not interactive or not sys.stdin.isatty():
        return
    try:
        if RICH_CONSOLE is not None:
            RICH_CONSOLE.print()
            RICH_CONSOLE.input("[bold cyan]运行结束. 按回车键关闭窗口...[/bold cyan]")
        else:
            input("\n运行结束. 按回车键关闭窗口...")
    except (EOFError, KeyboardInterrupt):
        pass


def main() -> int:
    args = create_default_config()
    exit_code = 0
    try:
        ensure_dependencies()
        init_rich_ui()
        if len(sys.argv) > 1:
            ui_print(
                "[yellow]当前版本仅支持交互模式, 命令行参数已忽略.[/yellow]"
                if RICH_CONSOLE
                else "当前版本仅支持交互模式, 命令行参数已忽略."
            )
        if args.interactive:
            args = configure_interactively(args)
        asyncio.run(async_main(args))
    except KeyboardInterrupt:
        ui_print(
            "[yellow]已中断；下次运行可从最近的检查点继续。[/yellow]"
            if RICH_CONSOLE
            else "\n已中断；下次会从最近的检查点继续。"
        )
        exit_code = 130
    except Exception as exc:
        ui_print(
            f"[bold red]错误：{type(exc).__name__}: {exc}[/bold red]"
            if RICH_CONSOLE
            else f"错误：{type(exc).__name__}: {exc}"
        )
        exit_code = 1
    finally:
        pause_before_exit(args.interactive)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
