"""Shared immutable HTTPS inputs, without test execution or test-name rosters."""
import ipaddress, json, os, re, socket, sys
from t2_processes import subprocess

def local_address():
    if os.environ.get("SOURCE_T2_ADDRESS"):
        candidates = [os.environ["SOURCE_T2_ADDRESS"]]
    elif sys.platform == "darwin":
        interfaces = subprocess.check_output(["/sbin/ifconfig"], text=True)
        candidates = re.findall(r"\binet (\d+\.\d+\.\d+\.\d+)", interfaces)
    else:
        interfaces = json.loads(subprocess.check_output(["ip", "-j", "-4", "address", "show"], text=True))
        candidates = [entry["local"] for interface in interfaces for entry in interface["addr_info"]]
    for address in candidates:
        ip = ipaddress.ip_address(address)
        if ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_multicast:
            continue
        # Bind before probing so no request is sent to an unrelated remote endpoint.
        try:
            with socket.socket() as listener:
                listener.bind((address, 0))
                listener.listen(1)
                listener.settimeout(0.25)
                with socket.create_connection(listener.getsockname(), timeout=0.25):
                    with listener.accept()[0]:
                        return address
        except OSError:
            continue
    raise RuntimeError("no reachable non-loopback local IPv4 address; set SOURCE_T2_ADDRESS")

def tls_environment(root, context):
    address=local_address()
    context.source_tls(root)
    return dict(os.environ,SOURCE_T2_TLS=str(root),SOURCE_T2_ADDRESS=address)
