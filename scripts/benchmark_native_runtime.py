"""Two persistent native Agents for the finite synthetic capacity harness only."""
import json
import os
from pathlib import Path
import select
import shutil
import subprocess
import tempfile
import threading

DRIVER = r'''
import child from 'node:child_process';
import {syncBuiltinESMExports} from 'node:module';
import {createInterface} from 'node:readline';
let subprocessCalls=0;
const deny=()=>{subprocessCalls++;throw Error('native Agent must not delegate to a subprocess');};
for(const name of ['spawn','spawnSync','exec','execSync','execFile','execFileSync','fork'])child[name]=deny;
syncBuiltinESMExports();
const {Agent}=await import('./agent.ts');
const {OpenDeliveryClient}=await import('./open-delivery-client.ts');
let agent;
for await(const line of createInterface({input:process.stdin,crlfDelay:Infinity})){
  if(Buffer.byteLength(line)>1048576)throw Error('finite synthetic input limit');
  let result;
  try{
    const request=JSON.parse(line);
    if(!agent){agent=new Agent(request.client_config,request.network_config);result={ready:true};}
    else if(request.capacity_metrics){result={cpu:process.cpuUsage(),rss:process.memoryUsage().rss,subprocessCalls,
      distribution:typeof OpenDeliveryClient.prototype.freezeDispatch==='function'};}
    else result=await agent.handle(request);
  }catch(error){result={synthetic_driver_error:error.code??error.name};}
  process.stdout.write(JSON.stringify(result)+'\n');
}
'''


class NativeAgent:
    def __init__(self,node,directory,agent):
        self.lock=threading.Lock()
        self.process=subprocess.Popen([node,'--experimental-strip-types',str(directory/'driver.mjs')],
            cwd=directory,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        self.handle(dict(client_config=str(agent.client_config),network_config=str(agent.network_config)))

    def handle(self,request):
        encoded=json.dumps(request,separators=(',',':')).encode()+b'\n'
        if len(encoded)>1048576:raise RuntimeError('finite native input limit')
        with self.lock:
            self.process.stdin.write(encoded);self.process.stdin.flush()
            if not select.select([self.process.stdout],[],[],60)[0]:raise TimeoutError('native synthetic reply deadline')
            reply=self.process.stdout.readline(1048577)
            if not reply or len(reply)>1048576:raise RuntimeError('native synthetic process/reply failure')
            result=json.loads(reply)
            if 'synthetic_driver_error' in result:raise RuntimeError(result['synthetic_driver_error'])
            return result

    def close(self):
        if self.process.poll() is None:
            self.process.terminate()
            try:self.process.wait(2)
            except subprocess.TimeoutExpired:self.process.kill();self.process.wait(2)
        for pipe in (self.process.stdin,self.process.stdout,self.process.stderr):pipe.close()


class NativeRuntime:
    def __init__(self,fixture,root):
        node=os.environ.get('MEMORY_VAULT_NODE') or shutil.which('node')
        if not node:raise RuntimeError('existing Node >=22.19 required')
        selected=os.environ.get('MEMORY_VAULT_JOSE_MODULE')
        package=Path(selected).expanduser().resolve().parents[2] if selected else root/'clients/typescript/network/node_modules/jose'
        metadata=json.loads((package/'package.json').read_text())
        if metadata.get('name')!='jose' or metadata.get('version')!='6.2.10':raise RuntimeError('locked existing jose 6.2.10 required')
        self.temporary=tempfile.TemporaryDirectory(prefix='synthetic-native-capacity-')
        directory=Path(self.temporary.name)
        source=root/'clients/typescript/network'
        for path in [*source.glob('*.ts'),source/'package.json']:shutil.copyfile(path,directory/path.name)
        shutil.copyfile(root/'memory_vault_open_capacity_schema.json',directory/'memory_vault_open_capacity_schema.json')
        (directory/'node_modules').mkdir();(directory/'node_modules/jose').symlink_to(package,target_is_directory=True)
        (directory/'driver.mjs').write_text(DRIVER)
        self.agents=[]
        try:
            for agent in (fixture.a,fixture.b):
                native=NativeAgent(node,directory,agent);self.agents.append(native);agent.handle=native.handle
        except BaseException:self.close();raise

    def usage(self):
        result=[agent.handle(dict(capacity_metrics=True)) for agent in self.agents]
        assert all(value['subprocessCalls']==0 for value in result)
        return result

    def close(self):
        for agent in self.agents:agent.close()
        self.temporary.cleanup()
