"""Real loopback HTTP and private I/O checks; no installation or public network."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


def prepare_runtime(cls, modules, driver):
    cls.node = shutil.which("node")
    if cls.node is None:
        raise unittest.SkipTest("Existing Node required")
    package = ROOT / "clients/typescript/network/node_modules/jose"
    selected = os.environ.get("MEMORY_VAULT_JOSE_MODULE")
    if selected:
        entry = Path(selected).expanduser().resolve()
        if entry.parts[-3:] != ("dist", "webapi", "index.js"):
            raise RuntimeError("Expected explicit jose/dist/webapi/index.js")
        package = entry.parents[2]
    if not (package / "package.json").is_file():
        raise unittest.SkipTest("Existing locked jose required; this test never installs dependencies")
    meta = json.loads((package / "package.json").read_bytes())
    if meta.get("name") != "jose" or meta.get("version") != "6.2.10":
        raise RuntimeError("Locked jose 6.2.10 required")
    cls.temporary = tempfile.TemporaryDirectory(prefix="memory-vault-ts-boundary-synthetic-")
    cls.addClassCleanup(cls.temporary.cleanup)
    cls.fixture = Path(cls.temporary.name).resolve()
    for name in (*modules, "package.json"):
        shutil.copyfile(ROOT / "clients/typescript/network" / name, cls.fixture / name)
    (cls.fixture / "node_modules").mkdir()
    (cls.fixture / "node_modules/jose").symlink_to(package, target_is_directory=True)
    (cls.fixture / "driver.mjs").write_text(driver)


def invoke(test, value):
    result = subprocess.run([test.node, "--experimental-strip-types", str(test.fixture / "driver.mjs")],
        input=json.dumps(value).encode(), capture_output=True, timeout=20, cwd=test.fixture)
    test.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace")[-2000:])
    return json.loads(result.stdout)


DRIVER = r"""
import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import https from 'node:https';
import { performance } from 'node:perf_hooks';
import { HTTPTransport, origin } from './transport.ts';
import { readPrivate, openPrivateDatabase, privateDirectory } from './io.ts';
import { MAX_DOCUMENT_BYTES } from './crypto.ts';
const input=JSON.parse(fs.readFileSync(0,'utf8'));
const capture=async operation=>{try{return {ok:true,value:await operation()};}catch(error){return {ok:false,code:error.code||error.name,retryable:error.retryable===true};}};
const listen=server=>new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',resolve);});
const stop=server=>new Promise(resolve=>{server.closeAllConnections();server.close(resolve);});
let result;
if(input.op==='origins'){
 result=[];for(const value of input.values)result.push(await capture(()=>{const base=origin(value),url=new URL(base+'/v1/status');return {base,path:url.pathname,query:url.search,fragment:url.hash};}));
}else if(input.op==='io'){
 const root=fs.mkdtempSync(path.join(process.cwd(),'private-'));fs.chmodSync(root,0o700);
 const file=path.join(root,'synthetic.json');fs.writeFileSync(file,'{"synthetic":true}',{mode:0o600});
 result={read:await capture(()=>readPrivate(file,1024).length),oversized:await capture(()=>readPrivate(file,1)),missing:await capture(()=>readPrivate(path.join(root,'absent'),100,true))};
 fs.chmodSync(file,0o644);result.publicMode=await capture(()=>readPrivate(file,100));fs.chmodSync(file,0o600);
 fs.linkSync(file,path.join(root,'hardlink'));result.hardlink=await capture(()=>readPrivate(file,100));fs.unlinkSync(path.join(root,'hardlink'));
 fs.symlinkSync(file,path.join(root,'symlink'));result.symlink=await capture(()=>readPrivate(path.join(root,'symlink'),100));
 fs.mkdirSync(path.join(root,'public'),{mode:0o755});result.publicDirectory=await capture(()=>privateDirectory(path.join(root,'public')));
 const db=openPrivateDatabase(path.join(root,'state.sqlite3'));try{db.exec('CREATE TABLE synthetic(value TEXT)');db.prepare('INSERT INTO synthetic VALUES(?)').run('synthetic-only');result.database={mode:fs.statSync(path.join(root,'state.sqlite3')).mode&0o777,journal:db.prepare('PRAGMA journal_mode').get().journal_mode,synchronous:db.prepare('PRAGMA synchronous').get().synchronous,value:db.prepare('SELECT value FROM synthetic').get().value};}finally{db.close();}
}else if(input.op==='http'){
 let finalHits=0;const timers=new Set();
 const server=http.createServer((request,response)=>{
  if(request.url==='/v1/redirect'){response.writeHead(302,{location:'/v1/final'});response.end('{}');}
  else if(request.url==='/v1/final'){finalHits++;response.end('{"ok":true}');}
  else if(request.url==='/v1/large'){response.writeHead(200,{'content-length':String(MAX_DOCUMENT_BYTES+1)});response.end();}
  else if(request.url==='/v1/chunked'){response.writeHead(200,{'transfer-encoding':'chunked'});response.end(Buffer.alloc(MAX_DOCUMENT_BYTES+1,0x20));}
  else if(request.url==='/v1/encoded'){response.writeHead(200,{'content-encoding':'gzip'});response.end('{}');}
  else if(request.url==='/v1/duplicate'){response.end('{"value":1,"value":2}');}
  else if(request.url==='/v1/slow'){const timer=setTimeout(()=>{timers.delete(timer);response.end('{}');},500);timers.add(timer);}
  else {let bytes=0;request.on('data',chunk=>bytes+=chunk.length);request.on('end',()=>response.end(JSON.stringify({received:bytes,method:request.method,path:request.url})));}
 });await listen(server);const transport=new HTTPTransport(),base='http://127.0.0.1:'+server.address().port;
 try{
  result={normal:await capture(()=>transport.request(base,'POST','/v1/echo',{synthetic:'data'}))};
  for(const route of ['redirect','large','chunked','encoded','duplicate'])result[route]=await capture(()=>transport.request(base,'GET','/v1/'+route));
  const start=performance.now();result.slow=await capture(()=>transport.request(base,'GET','/v1/slow',undefined,start+60));result.elapsed=performance.now()-start;result.finalHits=finalHits;
  transport.close();result.closed=await capture(()=>transport.request(base,'GET','/v1/echo'));
 }finally{transport.close();for(const timer of timers)clearTimeout(timer);await stop(server);}
}else if(input.op==='tls'){
 const server=https.createServer({key:fs.readFileSync(input.key),cert:fs.readFileSync(input.cert)},(request,response)=>response.end('{"synthetic":true}'));
 server.on('tlsClientError',()=>{});await listen(server);const base='https://127.0.0.1:'+server.address().port;
 const previous=process.env.NODE_TLS_REJECT_UNAUTHORIZED;
 try{
  delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;let transport=new HTTPTransport();try{result={normal:await capture(()=>transport.request(base,'GET','/v1/status'))};}finally{transport.close();}
  process.env.NODE_TLS_REJECT_UNAUTHORIZED='0';transport=new HTTPTransport();try{result.ambientDisabled=await capture(()=>transport.request(base,'GET','/v1/status'));}finally{transport.close();}
 }finally{if(previous===undefined)delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;else process.env.NODE_TLS_REJECT_UNAUTHORIZED=previous;await stop(server);}
}
process.stdout.write(JSON.stringify(result));
"""


class TypeScriptTransportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        prepare_runtime(cls, ("crypto.ts", "io.ts", "transport.ts"), DRIVER)

    def test_original_url_cannot_hide_route_in_fragment_or_query(self):
        values = ["http://127.0.0.1:18888#", "http://127.0.0.1:18888?", "http://@127.0.0.1:18888",
                  "http://127.1:18888", "http://2130706433:18888", "http://0177.0.0.1:18888",
                  "https://example.invalid:", "https://example.invalid:0", "https://example.invalid:65536",
                  "http://example.invalid", "https://example.invalid/path", "https://example.invalid\\path"]
        result = invoke(self, {"op": "origins", "values": values})
        for value, row in zip(values, result): self.assertFalse(row["ok"], value)
        allowed = invoke(self, {"op": "origins", "values": ["http://127.0.0.1:18888/", "http://localhost:18888", "http://[::1]:18888", "https://synthetic.invalid"]})
        for row in allowed:
            self.assertTrue(row["ok"], row)
            self.assertEqual((row["value"]["path"], row["value"]["query"], row["value"]["fragment"]), ("/v1/status", "", ""))

    def test_real_http_refuses_redirect_compression_excess_size_and_deadline(self):
        result = invoke(self, {"op": "http"})
        self.assertTrue(result["normal"]["ok"], result)
        self.assertEqual(result["normal"]["value"]["path"], "/v1/echo")
        for name in ("redirect", "large", "chunked", "encoded", "duplicate", "slow", "closed"):
            self.assertFalse(result[name]["ok"], (name, result))
        self.assertEqual(result["finalHits"], 0)
        self.assertLess(result["elapsed"], 1000)
        # Node timers truncate fractional milliseconds; either deadline code
        # is acceptable when the request still stops within the same budget.
        self.assertIn(result["slow"]["code"], {"network_budget_exhausted", "network_body_deadline_exceeded"})
        self.assertTrue(result["slow"]["retryable"])

    def test_private_io_rejects_public_files_links_and_unsafe_directories(self):
        result = invoke(self, {"op": "io"})
        self.assertTrue(result["read"]["ok"])
        self.assertIsNone(result["missing"]["value"])
        for name in ("oversized", "publicMode", "hardlink", "symlink", "publicDirectory"):
            self.assertFalse(result[name]["ok"], (name, result))
        self.assertEqual(result["database"], {"mode": 0o600, "journal": "wal", "synchronous": 2, "value": "synthetic-only"})

    def test_https_certificate_verification_cannot_be_disabled_by_ambient_env(self):
        openssl = shutil.which("openssl")
        if openssl is None: self.skipTest("Existing openssl required for a synthetic self-signed loopback certificate")
        key, cert = self.fixture / "synthetic-key.pem", self.fixture / "synthetic-cert.pem"
        result = subprocess.run([openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key),
            "-out", str(cert), "-subj", "/CN=synthetic.invalid", "-days", "1"], capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, "Synthetic certificate creation failed")
        key.chmod(0o600)
        result = invoke(self, {"op": "tls", "key": str(key), "cert": str(cert)})
        self.assertFalse(result["normal"]["ok"], result)
        self.assertFalse(result["ambientDisabled"]["ok"], result)


if __name__ == "__main__":
    unittest.main()
