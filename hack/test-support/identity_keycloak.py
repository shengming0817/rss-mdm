"""Disposable Keycloak for the two real host OIDC step-up tests. All credentials are per run."""
import hashlib
import hmac
from html.parser import HTMLParser
from http.cookiejar import CookieJar
import ipaddress
import json
from pathlib import Path
import secrets
import select
import signal
import socket
import socketserver
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid


def docker(*args):
    return subprocess.check_output(["docker", *args], text=True, timeout=90).strip()


class Relay(socketserver.ThreadingTCPServer):
    daemon_threads = True

    def verify_request(self, request, client):
        return client[0] == self.server_address[0]


class Connection(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            self.forward()
        except (ConnectionError, TimeoutError):
            pass

    def forward(self):
        with socket.create_connection(("127.0.0.1", self.server.port), timeout=10) as upstream:
            peers = [self.request, upstream]
            while readable := select.select(peers, [], [], 60)[0]:
                for source in readable:
                    data = source.recv(32768)
                    if not data:
                        return
                    peers[1 - peers.index(source)].sendall(data)


def serve(directory, callback):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as route:
        route.connect(("192.0.2.1", 9))
        address = route.getsockname()[0]
    if not any(ipaddress.ip_address(address) in ipaddress.ip_network(cidr)
               for cidr in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")):
        raise ValueError("the native T2 host requires an RFC1918 address for the private issuer")
    directory.mkdir(mode=0o700)
    with Relay((address, 0), Connection) as relay:
        origin = f"https://{address}:{relay.server_address[1]}"
        issuer = origin + "/realms/product"
        secret, password, otp = (secrets.token_urlsafe(32) for _ in range(3))
        subject = str(uuid.uuid4())
        config = dict(issuer=issuer, subject=subject, clientSecret=secret, cidr=address + "/32")
        (directory / "login.json").write_text(json.dumps(dict(password=password, otp=otp, issuer=issuer, callback=callback)))
        realm = json.loads(Path(__file__).with_name("keycloak-totp.json").read_text())
        realm.update(realm="product", enabled=True, sslRequired="all",
                     clients=[dict(clientId="host", secret=secret, publicClient=False, standardFlowEnabled=True,
                                   redirectUris=[callback], attributes={"pkce.code.challenge.method":"S256"})],
                     users=[dict(id=subject, username="employee", enabled=True, firstName="Test", lastName="Employee",
                                 email="employee@example.test", emailVerified=True, credentials=[
                        dict(type="password", value=password, temporary=False),
                        dict(type="otp", userLabel="test", secretData=json.dumps(dict(value=otp)),
                             credentialData=json.dumps(dict(digits=6,counter=0,period=30,algorithm="HmacSHA1",subType="totp")))])])
        (directory / "realm.json").write_text(json.dumps(realm))
        subprocess.run(["openssl","req","-x509","-newkey","rsa:2048","-nodes","-keyout",str(directory/"tls.key"),
                        "-out",str(directory/"tls.crt"),"-days","2","-subj","/CN=host-t2",
                        "-addext",f"subjectAltName=IP:{address}","-addext","basicConstraints=critical,CA:FALSE",
                        "-addext","extendedKeyUsage=serverAuth"], check=True, capture_output=True, timeout=30)
        image = json.loads((Path(__file__).resolve().parents[2]/"deployment/providers.lock.json").read_text())["keycloak"]
        name = "rss-identity-t2-" + uuid.uuid4().hex
        def stop(_signal, _frame):
            raise SystemExit(0)
        signal.signal(signal.SIGTERM, stop)
        try:
            # The containing directory is private. Bind only these three fixture inputs.
            mounts = []
            for local, remote in [("realm.json","/data/import/product.json"),("tls.crt","/conf/tls.crt"),("tls.key","/conf/tls.key")]:
                (directory/local).chmod(0o644)
                mounts.extend(["-v",f"{directory/local}:/opt/keycloak{remote}:ro"])
            docker("run","-d","--name",name,"-p","127.0.0.1::8443",*mounts,image,"start-dev","--import-realm",
                   "--http-enabled=false","--hostname="+origin,"--https-certificate-file=/opt/keycloak/conf/tls.crt",
                   "--https-certificate-key-file=/opt/keycloak/conf/tls.key")
            relay.port = int(docker("port",name,"8443/tcp").rsplit(":",1)[1])
            threading.Thread(target=relay.serve_forever,daemon=True).start()
            client = opener(directory)
            for _ in range(200):
                try:
                    with client.open(issuer+"/.well-known/openid-configuration",timeout=2) as response:
                        if json.load(response)["issuer"] == issuer:
                            break
                except OSError:
                    time.sleep(0.4)
            else:
                raise RuntimeError("Keycloak did not become ready")
            print(json.dumps(config),flush=True)
            sys.stdin.buffer.read()
        finally:
            subprocess.run(["docker","rm","-f",name], stdout=subprocess.DEVNULL,check=False,timeout=60)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def opener(directory):
    tls = ssl.create_default_context(cafile=str(directory/"tls.crt"))
    return urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=tls),
                                      urllib.request.HTTPCookieProcessor(CookieJar()), NoRedirect())


class Form(HTMLParser):
    def __init__(self, requested):
        super().__init__()
        self.requested = requested
        self.action = None

    def handle_starttag(self, tag, attrs):
        fields = dict(attrs)
        if tag=="form" and fields.get("id")==self.requested:
            self.action=fields["action"]


def authorize(directory):
    data=json.loads((directory/"login.json").read_text())
    url=sys.stdin.read().strip()
    client=opener(directory)
    if not url.startswith(data["issuer"]+"/"):
        raise ValueError("unexpected authorization endpoint")
    with client.open(url,timeout=10) as response:
        page=response.read().decode()
    for form in ["kc-form-login","kc-otp-login-form"]:
        parser=Form(form)
        parser.feed(page)
        if not parser.action or not parser.action.startswith(data["issuer"]+"/"):
            raise ValueError("expected Keycloak form absent")
        if form=="kc-form-login":
            values=dict(username="employee",password=data["password"],credentialId="")
        else:
            last=directory/"last-totp-counter"
            if last.exists():
                time.sleep(max(0,(int(last.read_text())+1)*30+0.2-time.time()))
            counter=int(time.time())//30
            last.write_text(str(counter))
            mac=hmac.new(data["otp"].encode(),counter.to_bytes(8,"big"),hashlib.sha1).digest()
            offset=mac[-1]&15
            otp=(int.from_bytes(mac[offset:offset+4],"big")&0x7fffffff)%1000000
            values=dict(otp=f"{otp:06d}",login="Log In")
        try:
            with client.open(parser.action,urllib.parse.urlencode(values).encode(),timeout=10) as response:
                page=response.read().decode()
        except urllib.error.HTTPError as response:
            location=response.headers.get("location","")
            if form=="kc-otp-login-form" and response.code in (302,303) and location.startswith(data["callback"]+"?"):
                print(location)
                return
            raise ValueError("unexpected Keycloak response") from None
    raise ValueError("Keycloak authentication did not redirect")


if __name__ == "__main__":
    if sys.argv[1]=="serve":
        serve(Path(sys.argv[2]),sys.argv[3])
    else:
        authorize(Path(sys.argv[2]))
