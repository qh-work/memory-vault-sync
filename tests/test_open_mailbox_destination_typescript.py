"""Native recipient authority drives real sender mailbox admission over HTTP."""
import base64
import json
import sqlite3
import subprocess
import unittest
import time
from pathlib import Path
from tests import test_open_delivery_http as fixture
from tests import test_open_ack_typescript_agent as runtime

class NativeMailboxDestinationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        runtime.NativeAckAgentTests.setUpClass.__func__(cls)

    def native(self,agent,requests):
        run=subprocess.run([self.node,'--experimental-strip-types',str(self.fixture/'driver.mjs')],cwd=self.fixture,
            input=json.dumps(dict(client_config=str(agent.client_config),network_config=str(agent.network_config),requests=requests,no_network=True)).encode(),
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=45)
        self.assertEqual(run.returncode,0,run.stderr.decode(errors='replace')[-2500:])
        result=json.loads(run.stdout);self.assertEqual(result['calls'],[]);self.assertEqual(result['subprocessCalls'],0)
        state=Path(json.loads(Path(agent.network_config).read_bytes())['state_directory'])/'network.sqlite3'
        db=sqlite3.connect(state)
        try:self.assertEqual(db.execute('PRAGMA integrity_check').fetchall(),[('ok',)])
        finally:db.close()
        return result['results']

    def test_native_authorizes_real_admission_and_python_reopens_exact_pages(self):
        self.journey(False)

    def test_native_authorization_rejects_conflicts_expiry_and_changed_receiver(self):
        self.journey(True)

    def test_expired_retained_revocation_blocks_cached_and_new_authorization(self):
        self.journey(False,True)

    def journey(self,negative,revoked=False):
        h=fixture.MailboxStagingHTTPTests('test_sender_admits_message_over_http');h.setUp();self.addCleanup(h.doCleanups)
        original=h.call;visited=[];pages=[];first=[]
        def dispatch(agent,**request):
            invitation=request.get('invitation',{})
            if agent is not h.b or invitation.get('schema_version')!='memory-vault-open-mailbox-connect/v1' or invitation.get('action') not in ('register','authorize'):
                return original(agent,**request)
            rows=self.native(agent,[request]);self.assertTrue(rows[0]['ok'],rows[0]);result=rows[0]['result']
            if invitation['action']=='register':
                self.assertEqual(result,original(agent,**request))
                inspected=self.native(agent,[dict(op='connect',invitation=dict(schema_version=invitation['schema_version'],action='inspect',receiver_id=result['receiver_id']))])[0]
                self.assertTrue(inspected['ok'],inspected);self.assertEqual(inspected['result'],original(agent,op='connect',invitation=dict(schema_version=invitation['schema_version'],action='inspect',receiver_id=result['receiver_id'])))
                return result
            # Each page reopens in a new native process, then Python reads the same exact originals.
            self.assertEqual(result,original(agent,**request));pages.append(base64.b64decode(result['authorization_chunk'],validate=True))
            if 'cursor' not in invitation:
                visited.append(True);first.append(dict(invitation))
                if negative:
                    cases=[(dict(invitation,expires_at=invitation['expires_at']-1),'repair_destination_conflict'),
                        (dict(invitation,status_revision=1),'repair_destination_revision_rollback'),
                        (dict(invitation,status_revision=4,expires_at=1),'repair_resource_expired'),
                        (dict(invitation,status_revision=4,status_until=1),'repair_resource_expired'),
                        (dict(invitation,cursor=dict(sha256='0'*64,offset=3072)),'open_invalid_mailbox_cursor'),
                        (dict(invitation,receiver_id='mailbox_'+'0'*64),'open_mailbox_receiver_missing')]
                    for changed,code in cases:
                        denied=self.native(agent,[dict(op='connect',invitation=changed)])[0]
                        self.assertFalse(denied['ok'],denied);self.assertEqual(denied['error']['code'],code,denied)
                    state=Path(json.loads(Path(agent.network_config).read_bytes())['state_directory'])/'network.sqlite3'
                    db=sqlite3.connect(state)
                    try:
                        self.assertEqual(db.execute('SELECT revision FROM open_mailbox_destinations ORDER BY revision').fetchall(),[(2,),(3,)])
                        row=db.execute('SELECT body FROM open_mailbox_receivers WHERE receiver_id=?',(invitation['receiver_id'],)).fetchone()
                        config=json.loads(row[0]);config['expected_sender']=config['expected_target']
                        db.execute('UPDATE open_mailbox_receivers SET body=? WHERE receiver_id=?',(json.dumps(config).encode(),invitation['receiver_id']));db.commit()
                    finally:db.close()
                    wrong=self.native(agent,[request])[0];self.assertFalse(wrong['ok']);self.assertEqual(wrong['error']['code'],'open_invalid_mailbox_receiver')
                    db=sqlite3.connect(state)
                    try:
                        db.execute('UPDATE open_mailbox_receivers SET body=? WHERE receiver_id=?',(row[0],invitation['receiver_id']));db.commit()
                    finally:db.close()
                    self.assertEqual(self.native(agent,[request])[0]['result'],result)
            return result
        h.call=dispatch;h.test_sender_admits_message_over_http();self.assertEqual(visited,[True]);self.assertGreater(len(pages),1)
        authorization=json.loads(b''.join(pages));self.assertEqual(authorization,h.sender_authorization)
        # The fixture performs actual admission, feed/body recovery and authority denial checks.
        self.assertIn('destination_entry',authorization);self.assertIn('owner_status_entry',authorization)
        if revoked:
            from memory_vault_open_provider import issue_status
            from memory_vault_open_repair_status import status_scope,authenticate_status_original
            from memory_vault_open_repair_state import DEFAULT_POLICY
            from memory_vault_open_repair_wire import RepairBudget
            from memory_vault_open_repair_client import MailboxSetupJournal
            from tests.test_open_repair_status import status_entry
            slot=json.loads(authorization['slot_entries']['slot']['raw'])['payload'];root=slot['slot_key']['root_key'];now=int(time.time())
            scope=dict(scope_kind='mailbox_slot',scope_id=status_scope(root,'mailbox_slot',slot['slot_key'],DEFAULT_POLICY,RepairBudget(DEFAULT_POLICY)))
            entry=status_entry(issue_status(h.bi,root=root,revision=99,entries=[dict(scope,minimum_document_revision=slot['revision'],status='revoked',operation_mask=127)],issued_at=now-10,valid_until=now-1))
            observed=authenticate_status_original(entry,expected_root=root,expected_signing_key=h.bi.public_descriptor(),at=now-10,allowed_scopes=[scope],policy=DEFAULT_POLICY,budget=RepairBudget(DEFAULT_POLICY))
            with h.b._network() as network:
                with network.participant.state.db() as db:
                    jobs=db.execute('SELECT job_key FROM open_mailbox_setup_jobs').fetchall();self.assertEqual(len(jobs),1)
                    MailboxSetupJournal(db).observe(jobs[0][0],observed)
            for revision in (3,100):
                denied=self.native(h.b,[dict(op='connect',invitation=dict(first[0],status_revision=revision))])[0]
                self.assertFalse(denied['ok']);self.assertEqual(denied['error']['code'],'repair_authority_revoked',denied)
                reopened=h.b.handle(dict(op='connect',invitation=dict(first[0],status_revision=revision)))
                self.assertFalse(reopened['ok']);self.assertEqual(reopened['error']['code'],'repair_authority_revoked',reopened)


if __name__=='__main__':unittest.main()
