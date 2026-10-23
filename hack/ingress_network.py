"""Reserve the real Compose ingress through Docker's concurrent default IPAM.

ref: moby v28.0.0 libnetwork/ipams/defaultipam/address_space.go
ref: compose v2.39.4 pkg/compose/create.go resolveOrCreateNetwork
"""
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile


class Ingress:
    def __init__(self, root, project, owner):
        if not all(re.fullmatch(r'[a-zA-Z0-9_.-]{1,128}', value) for value in (project, owner)):
            raise ValueError('invalid ingress owner')
        self.root=Path(root)
        self.project,self.owner=project,owner
        self.name=project+'_ingress'
        self.record=self.root/'ingress.json'
        self.labels={'com.docker.compose.project':project,'com.docker.compose.network':'ingress','rss.mdm.worktree':owner}

    @staticmethod
    def _run(*args):
        result=subprocess.run(['docker',*args],text=True,capture_output=True,timeout=30)
        if result.returncode:raise RuntimeError('ingress network '+args[0]+' failed')
        return result.stdout.strip()

    def _inspect(self):
        names=self._run('network','ls','--filter','name='+self.name,'--format','{{json .}}')
        matches=[row for line in names.splitlines() if (row:=json.loads(line))['Name']==self.name]
        if not matches:return None
        if len(matches)!=1:raise RuntimeError('ambiguous ingress network owner')
        network=json.loads(self._run('network','inspect',matches[0]['ID']))[0]
        if network['Name']!=self.name or network.get('Driver')!='bridge' or not network.get('Internal'):
            raise RuntimeError('invalid ingress network geometry')
        if any((network.get('Labels') or {}).get(key)!=value for key,value in self.labels.items()):
            raise RuntimeError('refusing foreign ingress network')
        pools=[pool for pool in network['IPAM']['Config'] if ipaddress.ip_network(pool['Subnet']).version==4]
        if len(pools)!=1:raise RuntimeError('one IPv4 ingress pool required')
        return dict(id=network['Id'],name=self.name,owner=self.owner,subnet=pools[0]['Subnet'],bridge_gateway=pools[0]['Gateway'])

    def _read(self):
        if self.record.is_symlink():raise RuntimeError('ingress record must not be a symlink')
        if not self.record.exists():return None
        value=json.loads(self.record.read_text())
        if set(value)!={'id','name','owner','subnet','bridge_gateway'} or value['name']!=self.name or value['owner']!=self.owner:
            raise RuntimeError('foreign or incomplete ingress record')
        return value

    @staticmethod
    def _addresses(record):
        pool=ipaddress.ip_network(record['subnet']);bridge=ipaddress.ip_address(record['bridge_gateway'])
        if pool.version!=4 or pool.num_addresses<8 or bridge not in pool:raise RuntimeError('invalid ingress pool')
        addresses=[]
        for address in pool.hosts():
            if address!=bridge:addresses.append(str(address))
            if len(addresses)==3:return addresses
        raise RuntimeError('ingress pool exhausted')

    def values(self):
        record=self._read()
        if record is None:return {}
        gateway,backend,_=self._addresses(record)
        return dict(MDM_INGRESS_SUBNET=record['subnet'],MDM_GATEWAY_ADDRESS=gateway,MDM_BACKEND_ADDRESS=backend)

    def validate(self):
        saved=self._read()
        if saved is None or saved!=self._inspect():
            raise RuntimeError('product ingress is not initialized or changed; reset and initialize the environment')
        return self.values()

    def address(self, index):
        record=self._read()
        if record is None:raise RuntimeError('ingress is not allocated')
        return self._addresses(record)[index]

    def _save(self, record):
        with tempfile.NamedTemporaryFile(mode='w',dir=self.root,delete=False) as stream:
            path=Path(stream.name)
            try:
                json.dump(record,stream);stream.flush();os.fsync(stream.fileno())
                path.replace(self.record)
            finally:path.unlink(missing_ok=True)

    def allocate(self):
        if self.root.is_symlink():raise RuntimeError('ingress root must not be a symlink')
        self.root.mkdir(parents=True,exist_ok=True,mode=0o700)
        descriptor=os.open(self.root/'ingress.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
        with os.fdopen(descriptor,'r+') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX)
            saved=self._read();actual=self._inspect()
            if saved is not None and saved!=actual:
                raise RuntimeError('ingress allocation changed; reset and initialize the owned environment')
            if actual is None:
                arguments=['network','create','--driver','bridge','--internal']
                for key,value in self.labels.items():arguments+=['--label',key+'='+value]
                try:
                    self._run(*arguments,self.name)
                    actual=self._inspect()
                    if actual is None:raise RuntimeError('ingress creation was not observed')
                    self._addresses(actual)
                    self._save(actual)
                except BaseException as error:
                    try:self.release()
                    except BaseException:error.add_note('ingress cleanup failed; retain owner record and inspect owned resources')
                    raise
            else:self._save(actual)
            return self.values()

    def release(self):
        saved=self._read();actual=self._inspect()
        if actual is not None:
            if saved is not None and saved!=actual:raise RuntimeError('ingress allocation changed; refusing removal')
            self._run('network','rm',actual['id'])
        self.record.unlink(missing_ok=True)
