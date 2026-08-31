"""Native TS SDK against a real loopback endpoint; synthetic records only.

Node's built-in type stripping runs the dependency-free SDK. A bounded ASGI
fault wrapper tests lost replies, redirects and reply-size handling without
introducing another Vault, credential scheme or protocol adapter.
"""
from __future__ import annotations

import asyncio
from collections import Counter
import json
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from memory_vault import canonical_bytes, failure
from memory_vault_agent import Agent, create_app
from memory_vault_client import CONFIG_SCHEMA, ClientConfig
from memory_vault_storage import atomic_write


class FaultEndpoint:
    """Pass normal calls to the official endpoint; fault only named fixtures."""

    def __init__(self, application, origin: str):
        self.application = application
        self.origin = origin
        self.requests: list[bytes] = []
        self.counts: Counter[str] = Counter()
        self.redirect_hits = 0

    async def __call__(self, scope, receive, send):
        from starlette.responses import JSONResponse, RedirectResponse
        if scope["type"] != "http":
            return await self.application(scope, receive, send)
        if scope["path"] == "/redirect-trap":
            self.redirect_hits += 1
            return await JSONResponse({"should_not_be_reached": True})(scope, receive, send)
        if scope["path"] != "/v1/agent":
            return await self.application(scope, receive, send)
        body = bytearray()
        while True:
            part = await receive()
            if part["type"] != "http.request":
                return
            body.extend(part.get("body", b""))
            if len(body) > 128 * 1024:
                return await JSONResponse(failure("request_too_large"), status_code=413)(scope, receive, send)
            if not part.get("more_body"):
                break
        self.requests.append(bytes(body))
        value = json.loads(body)
        request_id = value.get("request_id", "")
        self.counts[request_id] += 1
        if request_id == "req_ts_redirect_fixture":
            return await RedirectResponse(self.origin + "/redirect-trap", status_code=307)(scope, receive, send)
        if request_id == "req_ts_timeout_stream":
            encoded = canonical_bytes(failure("synthetic_stream_fixture"))
            await send({"type": "http.response.start", "status": 200,
                        "headers": [(b"content-type", b"application/json")]})
            await send({"type": "http.response.body", "body": encoded[:12], "more_body": True})
            await asyncio.sleep(0.5)
            await send({"type": "http.response.body", "body": encoded[12:], "more_body": False})
            return
        if request_id in {"req_ts_large_reply_header", "req_ts_large_reply_stream"}:
            response = {"schema_version": "universal-agent-memory-result/v1", "ok": True,
                        "result": {"fixture_padding": "x" * 9000}, "authority": {}, "request_id": request_id}
            encoded = canonical_bytes(response)
            headers = [(b"content-type", b"application/json")]
            if request_id.endswith("header"):
                headers.append((b"content-length", str(len(encoded)).encode()))
            await send({"type": "http.response.start", "status": 200, "headers": headers})
            await send({"type": "http.response.body", "body": encoded[:5000], "more_body": True})
            await send({"type": "http.response.body", "body": encoded[5000:], "more_body": False})
            return
        replayed = False

        async def replay():
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return await receive()

        async def delayed_send(message):
            # Agent.handle has committed before JSONResponse emits its start.
            # Delaying that reply reproduces an ambiguous successful write.
            if (request_id in {"req_ts_timeout_commit", "req_ts_cancel_commit"}
                    and self.counts[request_id] == 1 and message["type"] == "http.response.start"):
                await asyncio.sleep(0.5)
            await send(message)

        await self.application(scope, replay, delayed_send)


class NetworkTypeScriptTests(unittest.TestCase):
    def setUp(self):
        import uvicorn
        self.node = shutil.which("node")
        if self.node is None:
            self.fail("Node 22.19+ with built-in type stripping is required for this explicit network check")
        temporary = tempfile.TemporaryDirectory(prefix="memory-vault-ts-sdk-synthetic-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.config = self.root / "client.json"
        atomic_write(self.config, canonical_bytes({"schema_version": CONFIG_SCHEMA,
            "vault_path": str(self.root / "vault.sqlite3"), "capture_visible_turns": False}), replace=False)
        self.agent = Agent(self.config)
        self.token = "synthetic-ts-endpoint-token-not-a-real-secret"
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        self.origin = "http://127.0.0.1:" + str(listener.getsockname()[1])
        self.endpoint = FaultEndpoint(create_app(self.agent, bearer_token=self.token, base_url=self.origin), self.origin)
        self.server = uvicorn.Server(uvicorn.Config(self.endpoint, host="127.0.0.1", log_level="critical",
                                                  access_log=False, loop="asyncio", lifespan="off"))
        self.thread = threading.Thread(target=self.server.run, kwargs={"sockets": [listener]}, daemon=True)

        def stop():
            self.server.should_exit = True
            self.thread.join(timeout=5)
            listener.close()
            if self.thread.is_alive():
                raise AssertionError("synthetic loopback endpoint failed to stop")

        self.addCleanup(stop)
        self.thread.start()
        deadline = time.monotonic() + 5
        while not self.server.started and self.thread.is_alive() and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertTrue(self.server.started, "synthetic loopback endpoint did not start")

    def run_node(self, body: str) -> dict:
        sdk = (ROOT / "clients/typescript/index.ts").as_uri()
        script = f"import {{ MemoryVaultClient, MemoryVaultTransportError, OPERATIONS }} from {json.dumps(sdk)};\n"
        script += "import assert from 'node:assert/strict';\n"
        script += "const chunks=[]; for await (const chunk of process.stdin) chunks.push(chunk);\n"
        script += "const input=JSON.parse(Buffer.concat(chunks).toString('utf8'));\n"
        script += "const config={endpoint:input.origin,bearerToken:input.token,trustedEndpoint:true,allowLoopbackHttp:true,timeoutMs:3000};\n"
        script += body
        completed = subprocess.run([self.node, "--experimental-strip-types", "--input-type=module", "-e", script],
            input=canonical_bytes({"origin": self.origin, "token": self.token}), stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, cwd=ROOT, timeout=20)
        self.assertEqual(completed.returncode, 0, completed.stderr.decode()[-4000:])
        return json.loads(completed.stdout)

    def test_six_native_operations_share_core_records_errors_and_retry(self):
        result = self.run_node(r"""
const client=new MemoryVaultClient(config);
const discovery=await client.discover();
assert.equal(discovery.ok,true);
assert.deepEqual(discovery.result.operations,[...OPERATIONS]);
assert.equal(discovery.result.memory_owned_by_task,false);
const text='合成的跨运行时记忆🚀，不是权限。'.repeat(120);
const request={request_id:'req_ts_shared_record_01',kind:'fact',text};
const saved=await client.remember(request);
assert.equal(saved.ok,true);
assert.equal(saved.result.state,'accepted_local');
assert.deepEqual(await client.remember(request),saved);
const changed=await client.remember({...request,text:'changed under one request ID'});
assert.equal(changed.ok,false);
let page=await client.recall({memory_id:saved.result.memory_id});
let restored=''; let pages=0;
for (;;) {
  assert.equal(page.ok,true);
  restored+=page.result.hits.map(hit=>hit.text).join('');
  pages++;
  assert.ok(pages<32);
  if(page.result.next_cursor===null) break;
  page=await client.recall({cursor:page.result.next_cursor});
}
assert.equal(restored,text);
assert.ok(pages>1);
const connect=await client.connect({request_id:'req_ts_connect_unconfigured'});
const send=await client.send({request_id:'req_ts_send_unconfigured',recipients:['synthetic-peer'],text:'synthetic message'});
const receive=await client.receive({limit:1});
for(const response of [connect,send,receive]) {
  assert.equal(response.ok,false);
  assert.equal(response.error.code,'network_not_configured');
}
const forbidden=await client.remember({...request,request_id:'req_ts_no_task_parent_01',task_id:'not-an-owner'});
assert.equal(forbidden.ok,false);
const headers={authorization:'Bearer '+input.token};
assert.equal((await fetch(input.origin+'/.well-known/agent-card.json',{headers})).status,404);
assert.equal((await fetch(input.origin+'/message:send',{method:'POST',headers,body:'{}'})).status,404);
console.log(JSON.stringify({saved,changed,connect,send,receive,text,pages}));
""")
        saved = result["saved"]
        command = {"op": "remember", "request_id": "req_ts_shared_record_01", "kind": "fact", "text": result["text"]}
        self.assertEqual(self.agent.handle(command), saved)
        stored = ClientConfig.load(self.config).vault().handle({"op": "get", "memory_id": saved["result"]["memory_id"]})
        self.assertEqual(stored["result"]["record"]["text"], result["text"])
        self.assertEqual(self.agent.handle({**command, "text": "changed under one request ID"}), result["changed"])
        for operation, arguments in [("connect", {"request_id": "req_ts_connect_unconfigured"}),
                                     ("send", {"request_id": "req_ts_send_unconfigured", "recipients": ["synthetic-peer"], "text": "synthetic message"}),
                                     ("receive", {"limit": 1})]:
            self.assertEqual(self.agent.handle({"op": operation, **arguments}), result[operation])
        self.assertEqual(set(json.loads(body)["op"] for body in self.endpoint.requests),
                         {"connect", "remember", "recall", "discover", "send", "receive"})

    def test_endpoint_auth_budgets_redirect_and_explicit_transport_retry(self):
        result = self.run_node(r"""
const client=new MemoryVaultClient(config);
for(const invalid of [
  {...config,trustedEndpoint:false}, {...config,allowLoopbackHttp:false},
  {...config,endpoint:'http://remote.example'}, {...config,endpoint:input.origin+'/other'},
  {...config,endpoint:'https://user:password@example.test'}, {...config,maxRequestBytes:65537},
  {...config,maxResponseBytes:8193}, {...config,bearerToken:'bad\n'+'x'.repeat(40)},
]) assert.throws(()=>new MemoryVaultClient(invalid),MemoryVaultTransportError);
const unauthorized=await new MemoryVaultClient({...config,bearerToken:'wrong-synthetic-token-'+'x'.repeat(40)}).discover();
assert.equal(unauthorized.ok,false);
assert.equal(unauthorized.error.code,'endpoint_auth_required');
assert.equal(Object.hasOwn(unauthorized.error,'commit_state'),false);
async function failureOf(action,code,state) {
  try { await action(); assert.fail('expected SDK transport failure'); }
  catch(error) {
    assert.ok(error instanceof MemoryVaultTransportError);
    assert.equal(error.code,code);
    assert.equal(error.commit_state,state);
    return error;
  }
}
await failureOf(()=>client.remember({request_id:'req_ts_oversize_input',kind:'fact',text:'汉'.repeat(22000)}),'request_too_large','not_sent');
await failureOf(()=>client.remember({kind:'fact',text:'missing ID'}),'invalid_request_id','not_sent');
for(const suffix of ['header','stream']) {
  await failureOf(()=>client.remember({request_id:'req_ts_large_reply_'+suffix,kind:'fact',text:'synthetic'}),'response_too_large','unknown');
}
await failureOf(()=>client.remember({request_id:'req_ts_redirect_fixture',kind:'fact',text:'synthetic'}),'transport_failed','unknown');
await failureOf(()=>client.remember({request_id:'req_ts_timeout_stream',kind:'fact',text:'synthetic'},
  {timeoutMs:150}),'request_timeout','unknown');
const alreadyCancelled=new AbortController(); alreadyCancelled.abort();
await failureOf(()=>client.remember({request_id:'req_ts_cancel_before_send',kind:'fact',text:'synthetic'},
  {signal:alreadyCancelled.signal}),'request_cancelled','not_sent');
const timeoutRequest={request_id:'req_ts_timeout_commit',kind:'fact',text:'synthetic committed before timeout'};
const timeout=await failureOf(()=>client.remember(timeoutRequest,{timeoutMs:150}),'request_timeout','unknown');
assert.equal(timeout.request_id,'req_ts_timeout_commit');
timeoutRequest.request_id='req_ts_mutated_do_not_send';
timeoutRequest.text='must not replace frozen request';
const retried=await timeout.retry({timeoutMs:3000});
assert.equal(retried.ok,true);
assert.equal(retried.request_id,'req_ts_timeout_commit');
const cancelling=new AbortController();
const cancelTimer=setTimeout(()=>cancelling.abort(),150);
const cancelled=await failureOf(()=>client.remember({request_id:'req_ts_cancel_commit',kind:'fact',text:'synthetic committed before cancellation'},
  {signal:cancelling.signal,timeoutMs:3000}),'request_cancelled','unknown');
clearTimeout(cancelTimer);
const cancelRetry=await cancelled.retry();
assert.equal(cancelRetry.ok,true);
assert.equal(cancelRetry.request_id,'req_ts_cancel_commit');
console.log(JSON.stringify({unauthorized,retried,cancelRetry}));
""")
        self.assertEqual(result["unauthorized"], failure("endpoint_auth_required"))
        for request_id, text, result_key in [
            ("req_ts_timeout_commit", "synthetic committed before timeout", "retried"),
            ("req_ts_cancel_commit", "synthetic committed before cancellation", "cancelRetry"),
        ]:
            self.assertEqual(self.agent.handle({"op": "remember", "request_id": request_id, "kind": "fact", "text": text}),
                             result[result_key])
            attempts = [body for body in self.endpoint.requests if json.loads(body).get("request_id") == request_id]
            self.assertEqual(len(attempts), 2)
            self.assertEqual(attempts[0], attempts[1], "explicit retry must retain exact original request bytes")
        self.assertEqual(self.endpoint.redirect_hits, 0)
        self.assertEqual(self.endpoint.counts["req_ts_redirect_fixture"], 1, "SDK must not retry automatically")
        for absent in ["req_ts_oversize_input", "req_ts_cancel_before_send", "req_ts_mutated_do_not_send"]:
            self.assertEqual(self.endpoint.counts[absent], 0)


if __name__ == "__main__":
    unittest.main()
