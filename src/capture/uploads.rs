//! Background upload queue: a small fixed-concurrency worker pool so a large
//! scan upload doesn't freeze the interactive shell. Jobs are enqueued from
//! the REPL, run on one of `concurrency` worker threads, and their outcome is
//! collected as a `Receipt` the REPL can print between prompts
//! (`poll_receipts`). `:exit` calls `drain` to block until every queued and
//! in-flight job has finished.
//!
//! Dependency-free by design: `std::sync::mpsc` hands jobs to workers, a
//! shared `Mutex<Vec<Receipt>>` collects finished receipts, and an
//! `Arc<(Mutex<usize>, Condvar)>` tracks outstanding (queued + in-flight)
//! work so `drain` can block without busy-waiting.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Condvar, Mutex};
use std::thread;

use crate::util::lock;

/// The outcome of a background job, collected by `poll_receipts`.
pub struct Receipt {
    pub handle: String,
    pub label: String,
    pub result: Result<String, String>,
}

type Job = Box<dyn FnOnce() -> anyhow::Result<String> + Send>;

struct Task {
    handle: String,
    label: String,
    job: Job,
}

/// Fixed-concurrency background upload queue.
pub struct Queue {
    sender: mpsc::Sender<Task>,
    next_handle: AtomicU64,
    receipts: Arc<Mutex<Vec<Receipt>>>,
    outstanding: Arc<(Mutex<usize>, Condvar)>,
}

/// Decrement the outstanding (queued + in-flight) job count and, if it just
/// hit zero, wake every `drain()` waiter. The single place this bookkeeping
/// lives — called both when a worker finishes a job (success, error, or
/// panic) and when `enqueue` has to roll back a job that never made it onto
/// the channel.
fn finish_one(outstanding: &(Mutex<usize>, Condvar)) {
    let (count_lock, cvar) = outstanding;
    let mut count = lock(count_lock);
    *count = count.saturating_sub(1);
    if *count == 0 {
        cvar.notify_all();
    }
}

impl Queue {
    /// Spawn `concurrency` worker threads, each looping on the shared job
    /// channel until it's closed (which only happens when the `Queue`, and
    /// so every `Sender` clone, is dropped).
    pub fn new(concurrency: usize) -> Queue {
        let (sender, receiver) = mpsc::channel::<Task>();
        let receiver = Arc::new(Mutex::new(receiver));
        let receipts = Arc::new(Mutex::new(Vec::new()));
        let outstanding = Arc::new((Mutex::new(0usize), Condvar::new()));

        for _ in 0..concurrency.max(1) {
            let receiver = Arc::clone(&receiver);
            let receipts = Arc::clone(&receipts);
            let outstanding = Arc::clone(&outstanding);
            thread::spawn(move || {
                loop {
                    // Only hold the receiver lock long enough to pull the
                    // next task off the channel — never while the job runs.
                    let task = {
                        let rx = lock(&receiver);
                        rx.recv()
                    };
                    let Ok(task) = task else {
                        break; // channel closed: no more work will arrive
                    };

                    // Catch a panicking job so it becomes an `Err` receipt
                    // instead of unwinding out of the worker: without this,
                    // the decrement + notify below would never run and a
                    // `drain()` waiting on this job would block forever.
                    let result = match catch_unwind(AssertUnwindSafe(|| (task.job)())) {
                        Ok(r) => r,
                        Err(_) => Err(anyhow::anyhow!("job panicked")),
                    };
                    let result = result.map_err(|e| e.to_string());
                    lock(&receipts).push(Receipt {
                        handle: task.handle,
                        label: task.label,
                        result,
                    });

                    // Always reached, regardless of how the job terminated.
                    finish_one(&outstanding);
                }
            });
        }

        Queue {
            sender,
            next_handle: AtomicU64::new(1),
            receipts,
            outstanding,
        }
    }

    /// Queue `job` for background execution; returns a monotonic `bgN`
    /// handle (`bg1`, `bg2`, …) the REPL can reference before it completes.
    pub fn enqueue(
        &self,
        label: String,
        job: Box<dyn FnOnce() -> anyhow::Result<String> + Send>,
    ) -> String {
        let n = self.next_handle.fetch_add(1, Ordering::SeqCst);
        let handle = format!("bg{n}");

        {
            let (count_lock, _) = &*self.outstanding;
            *lock(count_lock) += 1;
        }

        // The channel only fails to send if every worker has exited, which
        // never happens while `self` (and so `sender`) is alive.
        if self
            .sender
            .send(Task {
                handle: handle.clone(),
                label,
                job,
            })
            .is_err()
        {
            // No workers left to pick this up: undo the outstanding bump so
            // drain() doesn't wait forever on a job that will never run.
            finish_one(&self.outstanding);
        }

        handle
    }

    /// Drain and return every receipt completed so far. Cheap to call
    /// between REPL prompts.
    pub fn poll_receipts(&self) -> Vec<Receipt> {
        std::mem::take(&mut *lock(&self.receipts))
    }

    /// Block until every queued and in-flight job has finished. Used by
    /// `:exit` so the process doesn't disappear mid-upload.
    pub fn drain(&self) {
        let (count_lock, cvar) = &*self.outstanding;
        let guard = lock(count_lock);
        let _guard = cvar
            .wait_while(guard, |count| *count > 0)
            .unwrap_or_else(|e| e.into_inner());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::time::Duration;

    /// Run `drain()` on its own thread and wait for it to finish, bounded by
    /// `timeout`, handing `q` back on success. If `drain()` ever regresses to
    /// hanging (e.g. a panicking job skipping the decrement + notify), this
    /// fails the test loudly instead of hanging the suite silently.
    ///
    /// `Queue` owns an `mpsc::Sender`, which isn't `Sync`, so the queue is
    /// moved into the worker thread (rather than shared by reference) and
    /// sent back over a channel once `drain()` returns.
    fn drain_bounded(q: Queue, timeout: Duration) -> Queue {
        let (tx, rx) = mpsc::channel::<Queue>();
        thread::spawn(move || {
            q.drain();
            tx.send(q).ok();
        });
        rx.recv_timeout(timeout)
            .unwrap_or_else(|_| panic!("drain() did not return within {timeout:?}"))
    }

    #[test]
    fn enqueue_runs_job_and_yields_receipt() {
        let q = Queue::new(2);
        let (tx, rx) = mpsc::channel();
        let h = q.enqueue(
            "test".into(),
            Box::new(move || {
                tx.send(()).ok();
                Ok("done".into())
            }),
        );
        assert!(h.starts_with("bg"));
        rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
        let q = drain_bounded(q, Duration::from_secs(5));
        let receipts = q.poll_receipts();
        assert!(receipts.iter().any(|r| r.handle == h && r.result.is_ok()));
    }

    #[test]
    fn two_jobs_both_complete_and_drain_returns() {
        let q = Queue::new(2);
        let h1 = q.enqueue("one".into(), Box::new(|| Ok("first".into())));
        let h2 = q.enqueue("two".into(), Box::new(|| Err(anyhow::anyhow!("boom"))));

        let q = drain_bounded(q, Duration::from_secs(5));

        let receipts = q.poll_receipts();
        assert_eq!(receipts.len(), 2);
        assert!(receipts
            .iter()
            .any(|r| r.handle == h1 && r.result.as_deref() == Ok("first")));
        assert!(receipts.iter().any(|r| r.handle == h2 && r.result.is_err()));

        // A second drain with nothing queued must return immediately.
        let q = drain_bounded(q, Duration::from_secs(5));
        assert!(q.poll_receipts().is_empty());
    }

    /// Regression test for the panic-in-a-job bug: without `catch_unwind`
    /// around the job invocation, a panicking job unwinds out of the worker
    /// loop before the outstanding-count decrement + `Condvar` notify run,
    /// so `drain()` blocks forever. Enqueue a panicking job alongside a
    /// normal one and assert `drain()` still returns within a bounded time,
    /// and that the panicked job surfaces as an `Err` receipt rather than
    /// silently vanishing.
    #[test]
    fn panicking_job_still_completes_and_drain_returns() {
        let q = Queue::new(2);
        let h_panic = q.enqueue(
            "boom".into(),
            Box::new(|| panic!("deliberate panic for regression test")),
        );
        let h_ok = q.enqueue("fine".into(), Box::new(|| Ok("still fine".into())));

        let q = drain_bounded(q, Duration::from_secs(5));

        let receipts = q.poll_receipts();
        assert_eq!(receipts.len(), 2);
        assert!(receipts
            .iter()
            .any(|r| r.handle == h_panic && r.result.is_err()));
        assert!(receipts
            .iter()
            .any(|r| r.handle == h_ok && r.result.as_deref() == Ok("still fine")));

        // The worker that ran the panicking job must have kept looping:
        // confirm the queue still accepts and completes new work.
        let h_again = q.enqueue("after-panic".into(), Box::new(|| Ok("recovered".into())));
        let q = drain_bounded(q, Duration::from_secs(5));
        assert!(q
            .poll_receipts()
            .iter()
            .any(|r| r.handle == h_again && r.result.as_deref() == Ok("recovered")));
    }
}
