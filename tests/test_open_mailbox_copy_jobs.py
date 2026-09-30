"""A retained maintainer job survives a lost real commit response and restart."""
import json
import io
from contextlib import redirect_stdout
import time
import unittest
from unittest.mock import patch

from memory_vault import MemoryError, canonical_bytes
from memory_vault_open_client import OpenNetworkClient
from memory_vault_open_mailbox_copy_jobs import CopyJobs, main
from memory_vault_storage import file_lock, StorageError
from memory_vault_trust import _write_new_private
from tests import test_open_delivery_http as fixtures
from tests.test_open_repair_mailbox_feed_copy import FeedCopyFixture


class CopyJobTests(unittest.TestCase):
    def run_fixture(self, inspect):
        h = fixtures.MailboxStagingHTTPTests('test_actual_delivery_stages_exact_ciphertext_under_mailbox_resources')
        h.setUp(); self.addCleanup(h.doCleanups); h.ack_cold_return = True
        def receive(staging,slot,head):
            replica = FeedCopyFixture(self,h,staging,slot,head,message=True,lifetime=180)
            inspect(replica)
        h.inspect_committed_mailbox = receive
        h.test_actual_delivery_stages_exact_ciphertext_under_mailbox_resources()

    def test_retained_copy_resumes_after_source_closes_and_target_restarts(self):
        from tests.test_open_repair_mailbox_feed_copy import MailboxFeedCopyTests
        original = FeedCopyFixture.command; calls = []
        def command(h,name,request,config,**kwargs):
            if name!='copy-upload-message': return original(h,name,request,config,**kwargs)
            calls.append(name)
            # The maintainer has the exact consented snapshot. Its source database
            # is unavailable before the first real upload, including all retries.
            h.source.db.close()
            def cli(*args):
                output = io.StringIO()
                with redirect_stdout(output): code = main(['--network-config',str(config),*args])
                self.assertEqual(code,0,output.getvalue())
                return json.loads(output.getvalue())
            if len(calls)==1:
                bundle = h.directory/'queued-copy-request.json'
                _write_new_private(bundle,canonical_bytes(request))
                self.assertEqual(cli('queue','--job-id','synthetic_copy','--kind','message','--request',str(bundle))['phase'],'pending')
            with OpenNetworkClient(config) as network:
                jobs = CopyJobs(network)
                with patch.object(network.participant.transport,'request_repair',side_effect=AssertionError('queue contacted target')):
                    queued = jobs.queue('synthetic_copy',request,source_state='message')
                    self.assertEqual(jobs.queue('synthetic_copy',request,source_state='message'),queued)
                    with self.assertRaisesRegex(MemoryError,'open_copy_job_conflict'):
                        jobs.queue('synthetic_copy',request,source_state='message',lifetime=601)
                with file_lock(jobs.lock):
                    with self.assertRaisesRegex(StorageError,'open_copy_worker_busy'): jobs.run_once()
                if len(calls)==3:
                    with patch.object(network.participant.transport,'request_repair',side_effect=AssertionError('completed job repeated upload')):
                        self.assertEqual(jobs.run_once()['phase'],'idle')
                    self.assertEqual(jobs.inspect('synthetic_copy')['attempts'],2)
                else:
                    result = cli('run')
                    if len(calls)==1:
                        self.assertEqual(result['phase'],'pending',result)
                        self.assertEqual(result['error'],'open_network_unavailable')
                        self.assertEqual(jobs.run_once()['phase'],'idle')
                        time.sleep(2.1)
                        raise MemoryError(result['error'],retryable=True)
                    self.assertEqual(result['phase'],'complete',result)
                output = h.directory/('queued-copy-result-'+str(len(calls))+'.json')
                jobs.export('synthetic_copy',output)
                saved = json.loads(output.read_bytes())
                if len(calls)==3:
                    bad = dict(request,target_storage_epoch='synthetic_wrong_epoch')
                    jobs.queue('synthetic_denied',bad,source_state='message')
                    denied = jobs.run_once()
                    self.assertEqual(denied['phase'],'needs_attention',denied)
                    # Local re-registration never resets exhausted/refused work.
                    self.assertEqual(jobs.queue('synthetic_denied',bad,source_state='message')['attempts'],1)
                    self.assertEqual(jobs.run_once()['phase'],'idle')
                    jobs.remove('synthetic_copy')
                    with self.assertRaisesRegex(MemoryError,'open_copy_job_missing'): jobs.inspect('synthetic_copy')
                return saved
        with patch.object(FeedCopyFixture,'command',new=command):
            MailboxFeedCopyTests.http_roundtrip(self,message=True,commands=True,upload_only=True)
        self.assertEqual(len(calls),3)


if __name__=='__main__': unittest.main()
