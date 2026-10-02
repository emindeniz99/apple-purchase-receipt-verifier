"""Threads and processes. One ``Verifier`` serves several threads from its
pool, and answers each exactly as it answers one thread; worker processes
each hold their own (the deployment the README recommends), and a fork after
the module was compiled keeps answering. Answers are compared as strings:
the endpoint's response is the module's own text, so equal means identical."""

import json
import multiprocessing
import os
import threading
import unittest

from apple_purchase_receipt_verifier import Config, Environment, Verifier

from _support import fixture_text

G5 = fixture_text("public-receipts", "receipt-sandbox-g5.b64")
JWS = fixture_text("generated", "transaction.jws")
NOW = 1_760_000_000_000
BODY = json.dumps({"receipt-data": G5})
CORRUPT = json.dumps({"receipt-data": G5[:-8] + "AAAAAAA="})
GARBAGE = json.dumps({"receipt-data": "not a receipt"})


def rows(verifier: Verifier) -> "list[str]":
    """One answer per operation and outcome, as text."""
    return [
        verifier.verify_receipt_endpoint(Environment.SANDBOX, BODY),
        verifier.verify_receipt_endpoint(Environment.PRODUCTION, BODY),
        verifier.verify_receipt_endpoint(Environment.SANDBOX, CORRUPT),
        verifier.verify_receipt_endpoint(Environment.SANDBOX, GARBAGE),
        repr(verifier.verify_receipt(G5)),
        repr(verifier.verify_receipt(G5[:-8] + "AAAAAAA=")),
        repr(verifier.verify_receipt("not a receipt")),
        repr(verifier.verify_signed_data(JWS)),
        repr(verifier.verify_signed_data("a.b.c")),
    ]


def new_verifier() -> Verifier:
    return Verifier(Config(clock=lambda: NOW))


def in_a_worker(queue: "multiprocessing.Queue[list[str]]") -> None:
    queue.put(rows(new_verifier()))


class ThreadsTest(unittest.TestCase):
    def test_threads_get_the_single_thread_answers(self) -> None:
        verifier = new_verifier()
        single = rows(verifier)
        self.assertNotEqual(single[0], single[3], "the rows must tell outcomes apart")
        answers: list[list[str]] = []
        errors: list[BaseException] = []
        lock = threading.Lock()
        start = threading.Barrier(4)

        def work() -> None:
            try:
                start.wait(timeout=30)
                for _ in range(5):
                    got = rows(verifier)
                    with lock:
                        answers.append(got)
            except BaseException as error:
                with lock:
                    errors.append(error)

        threads = [threading.Thread(target=work) for _ in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=300)
        self.assertEqual([], errors)
        self.assertEqual(20, len(answers))
        for got in answers:
            self.assertEqual(single, got)

    def test_two_verifiers_on_two_threads_share_one_compiled_module(self) -> None:
        results: dict[int, list[str]] = {}

        def work(index: int) -> None:
            results[index] = rows(new_verifier())

        threads = [threading.Thread(target=work, args=(i,)) for i in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=300)
        self.assertEqual(results[0], results[1])
        self.assertEqual(rows(new_verifier()), results[0])


class ProcessesTest(unittest.TestCase):
    def test_a_worker_process_gets_the_same_answers(self) -> None:
        mine = rows(new_verifier())
        context = multiprocessing.get_context("spawn")
        queue: multiprocessing.Queue[list[str]] = context.Queue()
        workers = [context.Process(target=in_a_worker, args=(queue,)) for _ in range(2)]
        for worker in workers:
            worker.start()
        got = [queue.get(timeout=300) for _ in workers]
        for worker in workers:
            worker.join(timeout=60)
            self.assertEqual(0, worker.exitcode)
        self.assertEqual([mine, mine], got)

    @unittest.skipUnless(hasattr(os, "fork"), "fork is POSIX only")
    def test_a_forked_child_keeps_answering_from_the_parents_pool(self) -> None:
        verifier = new_verifier()
        mine = rows(verifier)  # the module is compiled and an instance is pooled
        read, write = os.pipe()
        pid = os.fork()
        if pid == 0:  # the child
            code = 3
            try:
                os.close(read)
                inherited = rows(verifier)
                fresh = rows(new_verifier())  # a Verifier made after the fork
                os.write(write, json.dumps([inherited == mine, fresh == mine]).encode())
                code = 0
            finally:
                os._exit(code)
        os.close(write)
        with os.fdopen(read) as pipe:
            report = json.loads(pipe.read())
        _, status = os.waitpid(pid, 0)
        self.assertEqual(0, os.waitstatus_to_exitcode(status))
        self.assertEqual([True, True], report)


if __name__ == "__main__":
    unittest.main()
