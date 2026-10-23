"""Geçit: Türkiye'deki DNS ve SNI engellerini sunucusuz aşan yerel proxy.

Engel iki katmanlıdır:
  1. DNS: ISS, engelli alan adları için engel sayfasının IP'sini döndürür.
     Geçit alan adlarını şifreli DNS (DoH) ile çözer.
  2. SNI: DPI, TLS el sıkışmasındaki (ClientHello) alan adını görünce bağlantıyı keser.
     Geçit ClientHello'yu alan adının ortasından böler; filtre adı tek parça göremez.

Tarayıcılar ve Discord, Windows proxy ayarı (PAC) üzerinden Geçit'i kullanır. Proxy ayarını
yok sayan Discord güncelleyicisi ise hosts dosyasıyla 127.0.0.1:443'e yönlendirilir.

Kullanım:
  python gecit.py              başlat (yöntemi otomatik seçer, sistem proxy'sini ayarlar)
  python gecit.py --install    bir kerelik kurulum (Discord güncelleyicisi, açılışta başlatma)
  python gecit.py --test       hangi yöntemin hangi sitede çalıştığını gösterir
  python gecit.py --uninstall  kurulumu ve tüm ayarları geri alır
"""

import argparse
import asyncio
import base64
import ctypes
import hashlib
import logging
import logging.handlers
import os
import queue
import re
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import time
from urllib.parse import urlsplit

log = logging.getLogger("gecit")

DOH_SERVERS = ["1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9"]
MODES = ["none", "tls", "tcp", "tls+tcp"]
PROBE_HOST = "discord.com"
TEST_HOSTS = ["discord.com", "gateway.discord.gg", "cdn.discordapp.com", "roblox.com", "wattpad.com"]

PAC = """function FindProxyForURL(url, host) {
  if (isPlainHostName(host) || dnsDomainIs(host, ".local") ||
      /^(127\\.|10\\.|192\\.168\\.|169\\.254\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.)/.test(host))
    return "DIRECT";
  return "PROXY 127.0.0.1:%d; DIRECT";
}
"""


# --- Şifreli DNS (DoH, RFC 8484) --------------------------------------------

def is_ip(host):
    try:
        socket.inet_pton(socket.AF_INET6 if ":" in host else socket.AF_INET, host)
        return True
    except OSError:
        return False


def dns_query(name):
    labels = name.encode("idna").split(b".")
    qname = b"".join(bytes([len(label)]) + label for label in labels) + b"\0"
    return struct.pack("!6H", 0, 0x0100, 1, 0, 0, 0) + qname + struct.pack("!2H", 1, 1)


def skip_name(msg, pos):
    while msg[pos]:
        if msg[pos] & 0xC0 == 0xC0:
            return pos + 2
        pos += msg[pos] + 1
    return pos + 1


def dns_answers(msg):
    """DNS cevabındaki A kayıtlarını ve en küçük TTL'yi döndürür."""
    qdcount, ancount = struct.unpack("!2H", msg[4:8])
    pos = 12
    for _ in range(qdcount):
        pos = skip_name(msg, pos) + 4
    ips, ttl = [], 3600
    for _ in range(ancount):
        pos = skip_name(msg, pos)
        rtype, _, rttl, rdlen = struct.unpack("!HHIH", msg[pos:pos + 10])
        pos += 10
        if rtype == 1 and rdlen == 4:
            ips.append(socket.inet_ntoa(msg[pos:pos + 4]))
            ttl = min(ttl, rttl)
        pos += rdlen
    return ips, ttl


async def read_http_response(reader):
    head = await reader.readuntil(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    status = int(lines[0].split()[1])
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip().lower()] = value.strip()
    if "content-length" in headers:
        body = await reader.readexactly(int(headers["content-length"]))
    elif "chunked" in headers.get("transfer-encoding", ""):
        body = b""
        while size := int((await reader.readuntil(b"\r\n")).split(b";")[0], 16):
            body += (await reader.readexactly(size + 2))[:-2]
        await reader.readuntil(b"\r\n")
    else:
        body = await reader.read()
    return status, headers, body


class Resolver:
    """DoH ile IPv4 çözümleyici; sonuçları TTL süresince önbellekte tutar."""

    def __init__(self, servers=DOH_SERVERS):
        self.servers = list(servers)
        self.ctx = ssl.create_default_context()
        self.idle = {server: [] for server in self.servers}
        self.cache = {}
        self.pending = {}

    async def resolve(self, host):
        if is_ip(host):
            return [host]
        host = host.lower().rstrip(".")
        if host == "localhost":
            return ["127.0.0.1"]
        hit = self.cache.get(host)
        if hit and hit[0] > time.monotonic():
            return hit[1]
        # Aynı ad için aynı anda gelen istekler tek bir sorguyu paylaşır.
        task = self.pending.get(host)
        if task is None:
            task = self.pending[host] = asyncio.ensure_future(self._lookup(host))
            task.add_done_callback(lambda _: self.pending.pop(host, None))
        return await asyncio.shield(task)

    async def _lookup(self, host):
        query = dns_query(host)
        error = None
        for server in list(self.servers):
            try:
                ips, ttl = dns_answers(await asyncio.wait_for(self._ask(server, query), 4))
            except Exception as e:
                error = e
                log.debug("DoH %s cevap vermedi: %r", server, e)
                # Çalışmayan sunucuyu sona al; sonraki sorgular beklemesin.
                self.servers.remove(server)
                self.servers.append(server)
                continue
            if not ips:
                raise LookupError(f"{host} için IPv4 adresi yok")
            self.cache[host] = (time.monotonic() + min(max(ttl, 60), 3600), ips)
            return ips
        raise LookupError(f"{host} çözülemedi ({error!r})")

    async def _ask(self, server, query):
        path = "/dns-query?dns=" + base64.urlsafe_b64encode(query).rstrip(b"=").decode()
        request = (f"GET {path} HTTP/1.1\r\nHost: {server}\r\n"
                   "Accept: application/dns-message\r\n\r\n").encode()
        while True:
            reused = bool(self.idle[server])
            if reused:
                reader, writer = self.idle[server].pop()
            else:
                reader, writer = await asyncio.open_connection(server, 443, ssl=self.ctx)
            try:
                writer.write(request)
                await writer.drain()
                status, headers, body = await read_http_response(reader)
            except BaseException as e:
                writer.close()
                if reused and isinstance(e, (OSError, asyncio.IncompleteReadError)):
                    continue  # bekleyen bağlantı sunucu tarafından kapatılmış; yenisini aç
                raise
            if headers.get("connection", "").lower() == "close":
                writer.close()
            else:
                self.idle[server].append((reader, writer))
            if status != 200:
                raise ConnectionError(f"HTTP {status}")
            return body


# --- ClientHello parçalama --------------------------------------------------

def extensions(hello):
    """TLS ClientHello kaydındaki uzantıları (tür, veri başlangıcı, uzunluk) olarak verir."""
    try:
        if hello[0] != 0x16 or hello[5] != 0x01:
            return
        pos = 5 + 4 + 2 + 32                                  # kayıt ve el sıkışma başlığı, sürüm, random
        pos += 1 + hello[pos]                                 # oturum kimliği
        pos += 2 + int.from_bytes(hello[pos:pos + 2], "big")  # şifre takımları
        pos += 1 + hello[pos]                                 # sıkıştırma yöntemleri
        end = pos + 2 + int.from_bytes(hello[pos:pos + 2], "big")
        pos += 2
        while pos + 4 <= end:
            ext, length = struct.unpack("!2H", hello[pos:pos + 4])
            yield ext, pos + 4, length
            pos += 4 + length
    except IndexError:
        return


def find_sni(hello):
    """TLS ClientHello kaydında sunucu adının (SNI) başlangıcını ve uzunluğunu bulur."""
    for ext, start, _ in extensions(hello):
        if ext == 0:  # server_name: liste uzunluğu(2), tür(1), ad uzunluğu(2), ad
            return start + 5, int.from_bytes(hello[start + 3:start + 5], "big")
    return None


def offers_tls13(hello):
    for ext, start, length in extensions(hello):
        if ext == 43:  # supported_versions: liste uzunluğu(1), ardından 2'şer baytlık sürümler
            return any(hello[i:i + 2] == b"\x03\x04" for i in range(start + 1, start + length, 2))
    return False


def fragments(first, mode):
    """İstemcinin ilk paketini, filtrenin alan adını tek parça göremeyeceği parçalara böler.

    tls      ClientHello'yu iki TLS kaydına böler, tek seferde gönderir
    tcp      ClientHello'yu iki TCP segmentine böler
    tls+tcp  iki TLS kaydı, ayrı TCP segmentlerinde
    """
    if mode == "none":
        return [first]
    sni = find_sni(first)
    if sni:
        cut = sni[0] + sni[1] // 2
        if mode == "tcp":
            return [first[:cut], first[cut:]]
        body = first[5:]
        records = [first[:3] + len(part).to_bytes(2, "big") + part
                   for part in (body[:cut - 5], body[cut - 5:])]
        return [b"".join(records)] if mode == "tls" else records
    host = re.search(rb"\r\nHost:[ \t]*([^\r]*)", first, re.I)
    if host:  # düz HTTP: Host başlığının ortasından böl
        cut = (host.start(1) + host.end(1)) // 2
        return [first[:cut], first[cut:]]
    return [first]


async def send_parts(writer, parts):
    for i, part in enumerate(parts):
        if i:
            await asyncio.sleep(0.01)  # parçalar ayrı TCP segmentlerinde gitsin
        writer.write(part)
        await writer.drain()


async def open_tcp(resolver, host, port):
    ips = await resolver.resolve(host)
    error = None
    for ip in ips[:3]:
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), 6)
        except OSError as e:
            error = e
            continue
        writer.get_extra_info("socket").setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        return reader, writer
    raise error


async def probe(resolver, host, mode):
    """Verilen yöntemle host'a gerçek bir TLS el sıkışması yapar; sertifika doğrulanmazsa hata verir."""
    reader, writer = await open_tcp(resolver, host, 443)
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    tls = ssl.create_default_context().wrap_bio(incoming, outgoing, server_hostname=host)
    try:
        try:
            tls.do_handshake()
        except ssl.SSLWantReadError:
            pass
        await send_parts(writer, fragments(outgoing.read(), mode))
        while True:
            data = await asyncio.wait_for(reader.read(65536), 6)
            if not data:
                raise ConnectionResetError("bağlantı kapatıldı")
            incoming.write(data)
            try:
                tls.do_handshake()
                return
            except ssl.SSLWantReadError:
                if out := outgoing.read():
                    writer.write(out)
    finally:
        writer.close()


async def pick_mode(resolver):
    for mode in MODES[1:]:
        try:
            await probe(resolver, PROBE_HOST, mode)
            return mode
        except (OSError, ssl.SSLError, LookupError) as e:
            log.debug("%s yöntemi çalışmadı: %r", mode, e)
    return None


# --- Proxy sunucusu (HTTP CONNECT, düz HTTP ve SOCKS5 aynı portta) ------------

def split_host_port(target, default_port):
    if target.startswith("["):
        host, _, rest = target[1:].partition("]")
        return host, int(rest[1:]) if rest.startswith(":") else default_port
    host, sep, port = target.rpartition(":")
    return (host, int(port)) if sep else (target, default_port)


async def pipe(reader, writer):
    try:
        while data := await reader.read(65536):
            writer.write(data)
            await writer.drain()
    except OSError:
        pass


class Gecit:
    def __init__(self, resolver, mode, port):
        self.resolver = resolver
        self.mode = mode
        self.port = port
        self.local_ctx = None  # yerel sertifikalı TLS sunucusu, ilk ihtiyaçta yüklenir

    async def handle(self, reader, writer):
        await self.guard(self.serve_proxy(reader, writer), writer)

    async def handle_sni(self, reader, writer):
        await self.guard(self.serve_sni(reader, writer), writer)

    async def guard(self, coro, writer):
        try:
            await coro
        except (OSError, EOFError, asyncio.LimitOverrunError) as e:
            log.debug("bağlantı koptu: %r", e)
        except Exception:
            log.exception("beklenmeyen hata")
        finally:
            writer.close()

    async def serve_proxy(self, reader, writer):
        first = await reader.readexactly(1)
        if first == b"\x05":
            await self.handle_socks5(reader, writer)
        else:
            await self.handle_http(first + await reader.readuntil(b"\r\n\r\n"), reader, writer)

    async def serve_sni(self, reader, writer):
        """hosts dosyasıyla 127.0.0.1:443'e yönlendirilen TLS bağlantılarını, ClientHello'daki
        alan adına bakarak gerçek sunucuya iletir. TLS 1.3'te şifre çözülmez."""
        hello = await reader.readexactly(5)
        hello += await reader.readexactly(int.from_bytes(hello[3:5], "big"))
        sni = find_sni(hello)
        if sni is None:
            return
        host = hello[sni[0]:sni[0] + sni[1]].decode("ascii")
        if not offers_tls13(hello):
            # TLS 1.2'de sunucu sertifikası şifresiz gider; filtre içindeki alan adını görüp
            # bağlantıyı sessizce boğar. Yerel sertifika varsa bağlantıyı burada karşıla,
            # yoksa programı boşuna bekletmemek için hemen kapat.
            if host in HOSTS_DOMAINS and os.path.exists(CERT_FILE):
                log.debug("%s: TLS 1.2 bağlantısı yerel sertifikayla karşılanıyor", host)
                await self.terminate_tls(reader, writer, hello, host)
            else:
                log.info("%s: istemci yalnızca TLS 1.2 kullanıyor, filtre bunu engeller; "
                         "bağlantı kapatıldı (gecit.py --install ile düzelir)", host)
            return
        if any(ip.startswith("127.") for ip in await self.resolver.resolve(host)):
            return  # kendimize bağlanıp döngüye girmeyelim
        upstream = await self.open(host, 443)
        if upstream is not None:
            await self.relay(reader, writer, *upstream, first=hello)

    async def terminate_tls(self, creader, cwriter, hello, host):
        """Yalnızca TLS 1.2 bilen programı (Discord güncelleyicisi) yerel sertifikayla karşılar,
        sunucuya ise Geçit üzerinden TLS 1.3 ile bağlanır; aradaki düz veriyi aktarır."""
        if self.local_ctx is None:
            self.local_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self.local_ctx.load_cert_chain(CERT_FILE, KEY_FILE)
        incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        local = self.local_ctx.wrap_bio(incoming, outgoing, server_side=True)
        incoming.write(hello)
        while True:
            try:
                local.do_handshake()
                break
            except ssl.SSLWantReadError:
                cwriter.write(outgoing.read())
                if not (data := await creader.read(65536)):
                    return
                incoming.write(data)
        cwriter.write(outgoing.read())

        # Sunucuya kendi proxy'miz üzerinden bağlan: ClientHello orada parçalanır.
        ureader, uwriter = await asyncio.open_connection("127.0.0.1", self.port)
        try:
            uwriter.write(f"CONNECT {host}:443 HTTP/1.1\r\n\r\n".encode())
            if b" 200 " not in (await ureader.readuntil(b"\r\n\r\n")).split(b"\r\n")[0]:
                return
            upstream_ctx = ssl.create_default_context()
            upstream_ctx.minimum_version = ssl.TLSVersion.TLSv1_3
            await uwriter.start_tls(upstream_ctx, server_hostname=host)

            async def client_to_server():
                data = b""  # ilk turda el sıkışmayla birlikte gelmiş veri varsa onu da işle
                try:
                    while True:
                        incoming.write(data)
                        try:
                            while plain := local.read(65536):
                                uwriter.write(plain)
                        except ssl.SSLWantReadError:
                            pass
                        except ssl.SSLZeroReturnError:
                            return  # program TLS bağlantısını düzgünce kapattı
                        cwriter.write(outgoing.read())
                        await uwriter.drain()
                        if not (data := await creader.read(65536)):
                            return
                except OSError:
                    pass

            async def server_to_client():
                try:
                    while data := await ureader.read(65536):
                        local.write(data)
                        cwriter.write(outgoing.read())
                        await cwriter.drain()
                except OSError:
                    pass

            tasks = [asyncio.ensure_future(client_to_server()), asyncio.ensure_future(server_to_client())]
            try:
                await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            finally:
                for task in tasks:
                    task.cancel()
        finally:
            uwriter.close()

    async def open(self, host, port):
        try:
            upstream = await open_tcp(self.resolver, host, port)
        except (OSError, LookupError, UnicodeError) as e:
            log.info("%s:%d bağlanılamadı: %s", host, port, e or type(e).__name__)
            return None
        log.debug("%s:%d bağlandı", host, port)
        return upstream

    async def handle_http(self, head, reader, writer):
        line, _, rest = head.partition(b"\r\n")
        method, target, version = line.decode("latin-1").split(" ", 2)
        if method == "CONNECT":
            host, port = split_host_port(target, 443)
            upstream = await self.open(host, port)
            if upstream is None:
                writer.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                return
            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await self.relay(reader, writer, *upstream)
            return
        if target.startswith("/"):
            await self.serve_local(target, writer)
            return
        # Düz HTTP: isteği sunucuya uygun hale getir; bağlantı başına tek istek.
        url = urlsplit(target)
        path = (url.path or "/") + (f"?{url.query}" if url.query else "")
        hop = (b"proxy-connection:", b"connection:", b"keep-alive:", b"proxy-authorization:")
        headers = [h for h in rest.split(b"\r\n") if h and not h.lower().startswith(hop)]
        request = (f"{method} {path} {version}\r\n".encode() + b"\r\n".join(headers)
                   + b"\r\nConnection: close\r\n\r\n")
        upstream = await self.open(url.hostname, url.port or 80)
        if upstream is None:
            writer.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
            return
        await self.relay(reader, writer, *upstream, first=request)

    async def handle_socks5(self, reader, writer):
        await reader.readexactly((await reader.readexactly(1))[0])
        writer.write(b"\x05\x00")  # kimlik doğrulama yok
        _, cmd, _, atyp = await reader.readexactly(4)
        if atyp == 1:
            host = socket.inet_ntoa(await reader.readexactly(4))
        elif atyp == 3:
            host = (await reader.readexactly((await reader.readexactly(1))[0])).decode()
        elif atyp == 4:
            host = socket.inet_ntop(socket.AF_INET6, await reader.readexactly(16))
        else:
            return
        port = int.from_bytes(await reader.readexactly(2), "big")
        if cmd != 1:  # yalnızca CONNECT
            writer.write(b"\x05\x07\x00\x01" + bytes(6))
            return
        upstream = await self.open(host, port)
        if upstream is None:
            writer.write(b"\x05\x04\x00\x01" + bytes(6))
            return
        writer.write(b"\x05\x00\x00\x01" + bytes(6))
        await self.relay(reader, writer, *upstream)

    async def serve_local(self, path, writer):
        if path.split("?")[0] == "/proxy.pac":
            status, body = "200 OK", (PAC % self.port).encode()
        else:
            status, body = "404 Not Found", b""
        writer.write(f"HTTP/1.1 {status}\r\nContent-Type: application/x-ns-proxy-autoconfig\r\n"
                     f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode() + body)
        await writer.drain()

    async def relay(self, creader, cwriter, ureader, uwriter, first=b""):
        """İki yönlü aktarım; istemcinin ilk paketi (ClientHello) parçalanarak gönderilir."""
        down = asyncio.ensure_future(pipe(ureader, cwriter))
        tasks = [down]
        try:
            if not first:
                read = asyncio.ensure_future(creader.read(65536))
                await asyncio.wait([down, read], return_when=asyncio.FIRST_COMPLETED)
                if not read.done():
                    read.cancel()
                    return  # sunucu, istemci hiçbir şey göndermeden bağlantıyı kapattı
                first = read.result()
            rest = b""
            if first[:1] == b"\x16" and len(first) >= 5:
                need = 5 + int.from_bytes(first[3:5], "big")
                while len(first) < need:
                    more = await asyncio.wait_for(creader.read(65536), 10)
                    if not more:
                        break
                    first += more
                first, rest = first[:need], first[need:]
            await send_parts(uwriter, fragments(first, self.mode) + ([rest] if rest else []))
            tasks.append(asyncio.ensure_future(pipe(creader, uwriter)))
            await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for task in tasks:
                task.cancel()
            uwriter.close()


# --- Windows sistem proxy ayarı ---------------------------------------------

INTERNET_SETTINGS = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"


def set_system_pac(url):
    """Windows proxy ayarını PAC adresine yönlendirir; url None ise kaldırır."""
    import winreg
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, INTERNET_SETTINGS, 0, winreg.KEY_SET_VALUE) as key:
        if url:
            winreg.SetValueEx(key, "AutoConfigURL", 0, winreg.REG_SZ, url)
        else:
            try:
                winreg.DeleteValue(key, "AutoConfigURL")
            except FileNotFoundError:
                pass
    # Açık uygulamalara ayarların değiştiğini bildir.
    wininet = ctypes.windll.wininet
    wininet.InternetSetOptionW(None, 39, None, 0)  # INTERNET_OPTION_SETTINGS_CHANGED
    wininet.InternetSetOptionW(None, 37, None, 0)  # INTERNET_OPTION_REFRESH


HOSTS_FILE = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), r"System32\drivers\etc\hosts")
# Proxy ayarını yok sayan programların engelli adresleri. Discord'un güncelleyicisi sistem
# DNS'ini ve yalnızca TLS 1.2 kullandığı için bu adres olmadan açılış ekranında takılıyor.
HOSTS_DOMAINS = ["updates.discord.com"]
HOSTS_MARK = "# gecit"

APP_DIR = os.path.dirname(os.path.abspath(__file__))
CERT_DIR = os.path.join(APP_DIR, "sertifika")
CA_FILE = os.path.join(CERT_DIR, "gecit-kok.crt")
CERT_FILE = os.path.join(CERT_DIR, "sunucu.crt")
KEY_FILE = os.path.join(CERT_DIR, "sunucu.key")
RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"


def update_hosts(install):
    """hosts dosyasındaki Geçit satırlarını ekler ya da kaldırır; gerekirse yönetici izni ister."""
    if not ctypes.windll.shell32.IsUserAnAdmin():
        flag = "--install-hosts" if install else "--remove-hosts"
        command = ("$ProgressPreference = 'SilentlyContinue'; "
                   f"Start-Process -FilePath '{sys.executable}' -Verb RunAs -Wait -WindowStyle Hidden "
                   f"-ArgumentList '\"{os.path.abspath(__file__)}\" {flag}'")
        encoded = base64.b64encode(command.encode("utf-16-le")).decode()
        subprocess.run(["powershell", "-NoProfile", "-EncodedCommand", encoded])
    else:
        # latin-1, dosyadaki her baytı olduğu gibi geri yazar.
        with open(HOSTS_FILE, encoding="latin-1") as f:
            lines = [line for line in f.read().splitlines() if not line.endswith(HOSTS_MARK)]
        if install:
            lines += [f"127.0.0.1 {domain} {HOSTS_MARK}" for domain in HOSTS_DOMAINS]
        with open(HOSTS_FILE, "w", encoding="latin-1") as f:
            f.write("\n".join(lines) + "\n")
        subprocess.run(["ipconfig", "/flushdns"], capture_output=True)
    return hosts_lines()


def hosts_lines():
    with open(HOSTS_FILE, encoding="latin-1") as f:
        return [line for line in f.read().splitlines() if line.endswith(HOSTS_MARK)]


def create_certificates():
    """Yalnızca HOSTS_DOMAINS için geçerli bir kök sertifika ve onun imzaladığı sunucu
    sertifikasını üretir. Kök sertifikanın anahtarı diske hiç yazılmaz; böylece kimse
    (Geçit dahil) bununla başka bir sertifika imzalayamaz."""
    import datetime
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    now = datetime.datetime.now(datetime.timezone.utc)
    names = [x509.DNSName(domain) for domain in HOSTS_DOMAINS]
    no_usage = dict.fromkeys(["digital_signature", "content_commitment", "key_encipherment",
                              "data_encipherment", "key_agreement", "key_cert_sign", "crl_sign",
                              "encipher_only", "decipher_only"], False)

    def builder(subject, issuer, public_key):
        return (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
                .public_key(public_key).serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(days=1))
                .not_valid_after(now + datetime.timedelta(days=3650)))

    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Gecit (yalnizca " + ", ".join(HOSTS_DOMAINS) + ")")])
    ca = (builder(ca_name, ca_name, ca_key.public_key())
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.KeyUsage(**no_usage | {"key_cert_sign": True, "crl_sign": True}), critical=True)
          # Windows bu kısıtı uygular: kök sertifika listedeki adlar dışında hiçbir şeyi onaylayamaz.
          .add_extension(x509.NameConstraints(permitted_subtrees=names, excluded_subtrees=None), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
          .sign(ca_key, hashes.SHA256()))
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (builder(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, HOSTS_DOMAINS[0])]), ca_name, key.public_key())
            .add_extension(x509.SubjectAlternativeName(names), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(**no_usage | {"digital_signature": True}), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256()))

    os.makedirs(CERT_DIR, exist_ok=True)
    with open(CA_FILE, "wb") as f:
        f.write(ca.public_bytes(serialization.Encoding.PEM))
    with open(CERT_FILE, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(KEY_FILE, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))


def ca_der():
    with open(CA_FILE) as f:
        return ssl.PEM_cert_to_DER_cert(f.read())


def ca_installed():
    return os.path.exists(CA_FILE) and any(cert == ca_der() for cert, _, _ in ssl.enum_certificates("ROOT"))


def set_autostart(enable):
    """Geçit'i Windows oturumu açılınca küçültülmüş pencerede başlatır ya da bunu kaldırır."""
    import winreg
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
        if enable:
            bat = os.path.join(APP_DIR, "Gecit.bat")
            winreg.SetValueEx(key, "Gecit", 0, winreg.REG_SZ, f'cmd.exe /c start "Gecit" /min "{bat}"')
        else:
            try:
                winreg.DeleteValue(key, "Gecit")
            except FileNotFoundError:
                pass


def install():
    if not os.path.exists(CERT_FILE):
        try:
            create_certificates()
        except ImportError:
            print("Sertifika üretmek için önce şunu çalıştır: python -m pip install cryptography")
            return
    if not ca_installed():
        print("Windows, Geçit sertifikasını yüklemek isteyip istemediğini soracak: 'Evet'e bas.")
        subprocess.run(["certutil", "-user", "-addstore", "Root", CA_FILE], capture_output=True)
    if not ca_installed():
        print("Sertifika yüklenmedi; o olmadan Discord'un güncelleyicisi çalışamaz. Kurulum yarıda kaldı.")
        return
    print("Sertifika (yalnızca " + ", ".join(HOSTS_DOMAINS) + "): yüklü")
    lines = hosts_lines()
    if lines != [f"127.0.0.1 {domain} {HOSTS_MARK}" for domain in HOSTS_DOMAINS]:
        lines = update_hosts(True)  # yönetici izni ister
    print("hosts yönlendirmesi:", *lines or ["EKLENEMEDİ"])
    set_autostart(True)
    print("Windows açılışında başlatma: açık")


def uninstall():
    set_autostart(False)
    print("Windows açılışında başlatma: kapalı")
    if os.path.exists(CA_FILE):
        if ca_installed():
            print("Windows, Geçit sertifikasını silmek isteyip istemediğini soracak: 'Evet'e bas.")
            thumbprint = hashlib.sha1(ca_der()).hexdigest()
            subprocess.run(["certutil", "-user", "-delstore", "Root", thumbprint], capture_output=True)
        if ca_installed():
            print("Sertifika: SİLİNEMEDİ")
        else:
            shutil.rmtree(CERT_DIR)
            print("Sertifika: silindi")
    if hosts_lines():
        update_hosts(False)  # yönetici izni ister
    print("hosts yönlendirmesi:", "KALDIRILAMADI" if hosts_lines() else "kaldırıldı")
    set_system_pac(None)
    print("Windows proxy ayarı: kaldırıldı")


def keep_console_responsive():
    """Konsol penceresine tıklamak "seçim modunu" açar; o sırada ekrana yazan her şey, dolayısıyla
    tüm proxy donar. Hızlı düzenleme (fareyle seçim) modunu kapat."""
    kernel32 = ctypes.windll.kernel32
    handle = kernel32.GetStdHandle(-10)  # STD_INPUT_HANDLE
    mode = ctypes.c_uint()
    if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
        # ENABLE_QUICK_EDIT_MODE (0x40) kapalı; değişikliğin geçmesi için ENABLE_EXTENDED_FLAGS (0x80) açık.
        kernel32.SetConsoleMode(handle, (mode.value & ~0x0040) | 0x0080)


def on_console_close(callback):
    """Konsol penceresi kapatılınca callback'i çalıştırır; dönen nesne saklanmalıdır."""
    handler_type = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_uint)

    def handler(event):
        if event in (2, 5, 6):  # pencere kapatma, oturum kapatma, bilgisayarı kapatma
            callback()
        return False

    handler = handler_type(handler)
    ctypes.windll.kernel32.SetConsoleCtrlHandler(handler, True)
    return handler


# --- Ana program ------------------------------------------------------------

def quiet_exception_handler(loop, context):
    # Windows'ta karşı tarafın kapattığı bağlantılar gürültülü uyarılar üretir.
    if not isinstance(context.get("exception"), OSError):
        loop.default_exception_handler(context)


async def serve(args):
    asyncio.get_running_loop().set_exception_handler(quiet_exception_handler)
    resolver = Resolver()
    mode = args.mode
    if mode == "auto":
        log.info("Engel aşma yöntemi seçiliyor (%s üzerinde deneniyor)...", PROBE_HOST)
        mode = await pick_mode(resolver)
        if mode is None:
            log.warning("Hiçbir yöntem %s adresine ulaşamadı; 'tls' ile devam ediliyor.", PROBE_HOST)
            mode = "tls"
    gecit = Gecit(resolver, mode, args.port)
    server = await asyncio.start_server(gecit.handle, "127.0.0.1", args.port)
    try:
        await asyncio.start_server(gecit.handle_sni, "127.0.0.1", 443)
    except OSError as e:
        log.warning("443 portu açılamadı, hosts yönlendirmesi çalışmayacak: %s", e)
    if not args.no_system_proxy:
        set_system_pac(f"http://127.0.0.1:{args.port}/proxy.pac?{int(time.time())}")
        log.info("Windows proxy ayarı Geçit'e yönlendirildi (tarayıcılar ve Discord artık Geçit'ten geçiyor).")
    log.info("Geçit hazır: 127.0.0.1:%d, yöntem: %s. Kapatmak için bu pencereyi kapat.", args.port, mode)
    async with server:
        await server.serve_forever()


async def fetch_via_proxy(port, host):
    """Tarayıcı gibi davranır: proxy'ye CONNECT, ardından TLS ve gerçek bir HTTPS isteği."""
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        writer.write(f"CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n".encode())
        reply = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 10)
        if b" 200 " not in reply.split(b"\r\n")[0]:
            raise ConnectionError(reply.split(b"\r\n")[0].decode())
        await asyncio.wait_for(writer.start_tls(ssl.create_default_context(), server_hostname=host), 10)
        writer.write(f"HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
        return (await asyncio.wait_for(reader.readline(), 10)).decode().strip()
    finally:
        writer.close()


async def run_tests(hosts):
    resolver = Resolver()
    loop = asyncio.get_running_loop()
    best = await pick_mode(resolver) or "tls"
    server = await asyncio.start_server(Gecit(resolver, best, 0).handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    for host in hosts:
        try:
            system_ip = (await loop.getaddrinfo(host, 443, family=socket.AF_INET))[0][4][0]
        except OSError:
            system_ip = "çözülemedi"
        try:
            real_ip = (await resolver.resolve(host))[0]
        except (OSError, LookupError) as e:
            print(f"{host}: DoH hatası: {e}")
            continue
        results = []
        for mode in MODES:
            start = time.monotonic()
            try:
                await probe(resolver, host, mode)
                results.append(f"{mode}: OK ({(time.monotonic() - start) * 1000:.0f} ms)")
            except (OSError, ssl.SSLError, LookupError) as e:
                results.append(f"{mode}: X ({type(e).__name__})")
        try:
            via_proxy = await fetch_via_proxy(port, host)
        except (OSError, ssl.SSLError, EOFError) as e:
            via_proxy = f"X ({type(e).__name__}: {e})"
        print(f"{host}\n  sistem DNS: {system_ip}   DoH: {real_ip}\n  " + " | ".join(results)
              + f"\n  Geçit üzerinden: {via_proxy}")
    server.close()


def main():
    parser = argparse.ArgumentParser(description="Geçit: sunucusuz DNS/SNI engeli aşma proxy'si")
    parser.add_argument("--port", type=int, default=8881)
    parser.add_argument("--mode", choices=["auto"] + MODES, default="auto")
    parser.add_argument("--no-system-proxy", action="store_true",
                        help="Windows proxy ayarına dokunma (proxy'yi elle ayarlayacaksan)")
    parser.add_argument("--test", nargs="*", metavar="SITE",
                        help="yöntemleri sitelerde dene (varsayılan: Discord ve birkaç engelli site)")
    parser.add_argument("--off", action="store_true", help="Windows proxy ayarını kaldır ve çık")
    parser.add_argument("--install", action="store_true",
                        help="bir kerelik kurulum: Discord güncelleyicisi için sertifika ve hosts "
                             "yönlendirmesi, Windows açılışında başlatma")
    parser.add_argument("--uninstall", action="store_true", help="kurulumu ve tüm ayarları geri al")
    # update_hosts bunlarla kendini yönetici olarak yeniden çalıştırır.
    parser.add_argument("--install-hosts", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--remove-hosts", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()
    # Loglar ayrı bir iş parçacığında yazılır: konsol takılsa bile proxy beklemez.
    console = logging.StreamHandler()
    console.setFormatter(logging.Formatter("%(asctime)s %(message)s", datefmt="%H:%M:%S"))
    log_queue = queue.SimpleQueue()
    listener = logging.handlers.QueueListener(log_queue, console)
    listener.start()
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        handlers=[logging.handlers.QueueHandler(log_queue)])
    try:
        run(args)
    finally:
        listener.stop()


def run(args):
    if args.install_hosts or args.remove_hosts:
        update_hosts(args.install_hosts)
        return
    if args.install:
        install()
        return
    if args.uninstall:
        uninstall()
        return
    if args.off:
        set_system_pac(None)
        print("Windows proxy ayarı kaldırıldı.")
        return
    if args.test is not None:
        asyncio.run(run_tests(args.test or TEST_HOSTS))
        return

    keep_console_responsive()
    keep_alive = None
    if not args.no_system_proxy:
        keep_alive = on_console_close(lambda: set_system_pac(None))
    try:
        asyncio.run(serve(args))
    except KeyboardInterrupt:
        pass
    except OSError as e:
        log.error("Port %d açılamadı (Geçit zaten çalışıyor olabilir): %s", args.port, e)
    finally:
        if keep_alive:
            set_system_pac(None)
            log.info("Windows proxy ayarı geri alındı.")


if __name__ == "__main__":
    main()
