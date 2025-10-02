//! A task queue on top of a key-value store.

use std::{cmp, error, fmt};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use url::Url;
use crate::commons::storage::{
    Ident, KeyValueError, KeyValueStore, Transaction
};

//------------ Configuration -------------------------------------------------

macro_rules! separator { () => { "-" } }


//------------ Queue ---------------------------------------------------------

/// A task queue.
///
/// # Use of key-value store.
///
/// The queue uses a namespace handed in during creation. The first element
/// of the scope is “pending” for pending tasks and “running” for running
/// tasks. The second element is the Unix timestamp for when the task is
/// scheduled in milliseconds followed by a dash and the name.
#[derive(Debug)]
pub struct Queue {
    /// The key-value store the tasks are stored in.
    store: KeyValueStore,
}

impl Queue {
    /// The delay task that have timed out should be rescheudled after.
    const RESCHEDULE_AFTER: Duration = Duration::from_secs(15 * 60);

    /// The scope for the whole queue.
    const fn lock_scope() -> Option<&'static Ident> {
        None
    }

    /// The scope for pending tasks.
    const fn pending_scope() -> Option<&'static Ident> {
        Some(Ident::make("pending"))
    }

    /// The scope for running tasks.
    const fn running_scope() -> Option<&'static Ident> {
        Some(Ident::make("running"))
    }
}

impl Queue {
    /// Creates a new queue.
    pub fn create(
        storage_uri: &Url,
        namespace: &Ident,
    ) -> Result<Self, Error> {
        Ok(Queue {
            store: KeyValueStore::create(storage_uri, namespace)?,
        })
    }

    /// Returns the number of pending tasks remaining.
    pub fn pending_tasks_remaining(&self) -> Result<usize, Error> {
        Ok(self.store.execute(Self::lock_scope(), |kv| {
            kv.list_keys(Self::pending_scope()).map(|list| list.len())
        })?)
    }

    /// Returns the number of running tasks.
    pub fn running_tasks_remaining(&self) -> Result<usize, Error> {
        Ok(self.store.execute(Self::lock_scope(), |kv| {
            kv.list_keys(Self::running_scope()).map(|list| list.len())
        })?)
    }

    /// Returns the keys of the currently running tasks
    pub fn running_tasks_keys(&self) -> Result<Vec<Box<Ident>>, Error> {
        Ok(self.store.execute(Self::lock_scope(), |kv| {
            kv.list_keys(Self::running_scope())
        })?)
    }

    /// Schedule a new task.
    ///
    /// The task will be scheduled to be run at the given Unix timestamp or,
    /// if the timestamp is `None`, immediately.
    ///
    /// If a task with the same name already exists, then action depends on
    /// the `mode`.
    pub fn schedule_task(
        &self,
        name: &Ident,
        value: &serde_json::Value,
        timestamp_millis: Option<u128>,
        mode: ScheduleMode,
    ) -> Result<(), Error> {
        self.store.execute(Self::lock_scope(), |store| {
            let mut timestamp =  timestamp_millis.unwrap_or_else(|| {
                Self::now()
            });
            let pending_opt = self.get_storage_key_and_time(
                name, store, Self::pending_scope()
            );
            let running_opt = self.get_storage_key_and_time(
                name, store, Self::running_scope()
            );

            let keep = match mode {
                ScheduleMode::IfMissing => {
                    pending_opt.is_none() && running_opt.is_none()
                }
                ScheduleMode::ReplaceExisting => {
                    if let Some((pending, _)) = pending_opt {
                        store.delete(Self::pending_scope(), &pending)?;
                    }
                    true
                }
                ScheduleMode::ReplaceExistingSoonest => {
                    if let Some((pending, ts)) = pending_opt {
                        timestamp = cmp::min(
                            timestamp, ts
                        );
                        store.delete(Self::pending_scope(), &pending)?;
                    }
                    true
                }
                ScheduleMode::FinishOrReplaceExisting => {
                    if let Some((running, _)) = running_opt {
                        store.delete(Self::running_scope(), &running)?;
                    }
                    if let Some((pending, _)) = pending_opt {
                        store.delete(Self::pending_scope(), &pending)?;
                    }
                    true
                }
                ScheduleMode::FinishOrReplaceExistingSoonest => {
                    if let Some((running, _)) = running_opt {
                        store.delete(Self::running_scope(), &running)?;
                    }
                    if let Some((pending, ts)) = pending_opt {
                        timestamp = cmp::min(
                            timestamp, ts
                        );
                        store.delete(Self::pending_scope(), &pending)?;
                    }
                    true
                }
            };
            if keep {
                store.store(
                    Self::pending_scope(),
                    &Self::task_storage_key(name, Some(timestamp)),
                    value
                )?;
            }
            Ok(())
        })?;
        Ok(())
    }

    /// Returns the scheduled timestamp in ms for the named task, if any.
    pub fn pending_task_scheduled(
        &self, name: &Ident
    ) -> Result<Option<u128>, Error> {
        Ok(self.store.execute(Self::lock_scope(), |store| {
            store.list_keys(
                Self::pending_scope()
            ).map(|keys| {
                keys.into_iter().find_map(|key| {
                    let (ts, key_name) = Self::split_storage_key(&key)?;
                    (key_name == name).then_some(ts)
                })
            })
        })?)
    }

    /// Marks a running task as finished.
    ///
    /// Fails if the task is not running.
    pub fn finish_running_task(
        &self, storage_key: &Ident
    ) -> Result<(), Error> {
        self.store.execute(Self::lock_scope(), |store| {
            // XXX This should be done in a single step.
            if store.has(Self::running_scope(), storage_key)? {
                store.delete(Self::running_scope(), storage_key)?;
                Ok(Ok(()))
            }
            else {
                Ok(Err(Error::other(format!(
                    "Cannot finish task {storage_key}. It is not running."
                ))))
            }
        })?
    }

    /// Reschedules a running task as pending.
    ///
    /// Fails if the task is not running.
    pub fn reschedule_running_task(
        &self, storage_key: &Ident, timestamp_millis: Option<u128>
    ) -> Result<(), Error> {
        let Some((_, name)) = Self::split_storage_key(storage_key) else {
            return Err(Error::other(format!(
                "Cannot reschedule task {storage_key}: invalid storage key."
            )))
        };
        let new_key = Self::task_storage_key(name, timestamp_millis);
        Ok(self.store.execute(Self::lock_scope(), |store| {
            store.move_value(
                Self::running_scope(), storage_key,
                Self::pending_scope(), &new_key
            )
        })?)
    }

    /// Claims the next scheduled pending task, if any.
    pub fn claim_scheduled_pending_task(
        &self
    ) -> Result<Option<(Box<Ident>, serde_json::Value)>, Error> {
        self.store.execute(Self::lock_scope(), |store| {
            let now = Self::now();

            let Some((_, key)) = store.list_keys(
                Self::pending_scope()
            )?.into_iter().fold(None, |acc, key| {
                let Some((ts, _)) = Self::split_storage_key(&key) else {
                    return acc
                };
                if ts > now {
                    return acc
                }
                if let Some((acc_ts, _)) = acc && acc_ts < ts {
                    acc
                }
                else {
                    Some((ts, key))
                }
            }) else {
                return Ok(Ok(None))
            };

            let Some((_, name)) = Self::split_storage_key(&key) else {
                // We already did this just now, so this is impossible.
                return Ok(Err(Error::other(format!(
                    "Cannot load task: storage key '{key}' is suddenly \
                     invalid. This is a bug."
                ))));
            };

            if let Some(value) = store.get(Self::pending_scope(), &key)? {
                let mut new_key = Self::task_storage_key(name, Some(now));

                if store.has(Self::running_scope(), &new_key)? {
                    // It's not pretty to sleep blocking, even if it's
                    // for 1 ms, but if we don't then get a name collision
                    // with an existing running task.
                    std::thread::sleep(Duration::from_millis(1));
                    new_key = Self::task_storage_key(name, None);
                }

                store.move_value(
                    Self::pending_scope(), &key,
                    Self::running_scope(), &new_key
                )?;
                
                Ok(Ok(Some((new_key, value))))
            }
            else {
                Ok(Ok(None))
            }
        })?
    }

    /// Reschedules running tasks that have timed out.
    pub fn reschedule_long_running_tasks(
        &self, reschedule_after: Option<Duration>
    ) -> Result<(), Error> {
        let reschedule_after = reschedule_after.unwrap_or(
            Self::RESCHEDULE_AFTER
        );
        let reschedule_timeout = Self::now().saturating_sub(
            reschedule_after.as_millis()
        );

        Ok(self.store.execute(Self::lock_scope(), |store| {
            for key in store.list_keys(Self::running_scope())? {
                let Some((ts, name)) = Self::split_storage_key(&key) else {
                    continue
                };
                if ts <= reschedule_timeout {
                    let new_key = Self::task_storage_key(name, None);
                    let _ = store.move_value(
                        Self::running_scope(), &key,
                        Self::pending_scope(), &new_key
                    );
                }
            }
            Ok(())
        })?)
    }



    fn now() -> u128 {
        SystemTime::now().duration_since(
            UNIX_EPOCH
        ).map(|d| d.as_millis()).unwrap_or(0)
    }

    fn task_storage_key(
        name: &Ident, timestamp_millis: Option<u128>
    ) -> Box<Ident> {
        let timestamp_millis = timestamp_millis.unwrap_or_else(Self::now);

        // Safety: `name` is an ident and a formatted timestamp is only
        //         digits.
        unsafe {
            Ident::boxed_from_string_unchecked(
                format!(
                    concat!("{}", separator!(), "{}"),
                    timestamp_millis, name
                )
            )
        }
    }

    fn split_storage_key(key: &Ident) -> Option<(u128, &Ident)> {
        let (ts, name) = key.as_str().split_once(separator!())?;
        if name.is_empty() {
            return None
        }
        let ts = ts.parse().ok()?;

        // Safety: `name` is not empty and came from an Ident so characters
        //         are fine.
        //
        // XXX We should probably move all of this into
        //     crate::commons::storage::ident to concentrate the unsafe stuff
        //     there.
        let name = unsafe { Ident::from_bytes_unchecked(name.as_bytes()) };

        Some((ts, name))
    }

    fn get_storage_key_and_time(
        &self, name: &Ident, store: &mut Transaction, scope: Option<&Ident>
    ) -> Option<(Box<Ident>, u128)> {
        store.list_keys(scope).ok()?.into_iter().find_map(|key| {
            let (ts, key_name) = Self::split_storage_key(&key)?;
            (key_name == name).then_some((key, ts))
        })
    }
}


//------------ ScheduleMode --------------------------------------------------

/// Defines scheduling behaviour in case a task by the same name already exists.
#[derive(Clone, Copy, Debug)]
pub enum ScheduleMode {
    /// Store new task:
    /// - replace old task if it exists
    /// - do NOT finish old task
    ReplaceExisting,

    /// Store new task:
    /// - replace old task if it exists
    /// - use the soonest scheduled time if old task exists
    /// - do NOT finish old task if it is running
    ReplaceExistingSoonest,

    /// Store new task:
    /// - replace old task if it exists
    /// - finish old task if it is running
    FinishOrReplaceExisting,

    /// Store new task:
    /// - replace old task if it exists
    /// - use the soonest scheduled time if old task exists
    /// - finish old task if it is running
    FinishOrReplaceExistingSoonest,

    /// Keep existing pending or running task and in that case do not
    /// add the new task. Otherwise just add the new task.
    IfMissing,
}


//============ Errors Types ==================================================

//------------ InvalidKey ----------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct InvalidKey(());

impl fmt::Display for InvalidKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("invalid key")
    }
}

impl error::Error for InvalidKey { }


//------------ Error ---------------------------------------------------------

#[derive(Debug)]
pub struct Error(ErrorInner);

#[derive(Debug)]
enum ErrorInner {
    Store(KeyValueError),
    InvalidKey,
    Other(String),
}

impl Error {
    fn other(info: impl Into<String>) -> Self {
        Self(ErrorInner::Other(info.into()))
    }
}

impl From<KeyValueError> for Error {
    fn from(src: KeyValueError) -> Self {
        Self(ErrorInner::Store(src))
    }
}

impl From<InvalidKey> for Error {
    fn from(_: InvalidKey) -> Self {
        Self(ErrorInner::InvalidKey)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self.0 {
            ErrorInner::Store(inner) => inner.fmt(f),
            ErrorInner::InvalidKey => InvalidKey(()).fmt(f),
            ErrorInner::Other(inner) => f.write_str(inner)
        }
    }
}

impl error::Error for Error { }


//============ Tests =========================================================

#[cfg(test)]
mod tests {
    use std::thread;
    use std::time::Duration;
    use serde_json::Value;
    use url::Url;
    use super::*;

    fn queue_store(ns: &str) -> Queue {
        Queue::create(
            &Url::parse("memory://").unwrap(),
            Ident::from_str(ns).unwrap()
        ).unwrap()
    }

    #[test]
    fn key() {
        assert_eq!(
            Queue::task_storage_key(
                const { Ident::make("foo") },
                Some(12)
            ),
            const { Ident::make("12-foo") }.into()
        );
        assert_eq!(
            Queue::split_storage_key(const { Ident::make("12-foo") }),
            Some((12, const { Ident::make("foo") }))
        );
    }

    #[test]
    fn queue_thread_workers() {
        let queue = queue_store("queue_thread_workers");
        queue.store.wipe().unwrap();

        thread::scope(|s| {
            let create = s.spawn(|| {
                let queue = queue_store("queue_thread_workers");

                for i in 1..=10 {
                    let name = Ident::builder(
                        const { Ident::make("job-") }
                    ).push_u64(i).finish();
                    let value = Value::from("value");

                    queue.schedule_task(
                        &name,
                        &value,
                        None,
                        ScheduleMode::FinishOrReplaceExisting,
                    ).unwrap();
                    println!("> Scheduled job {}", &name);
                }
            });
            create.join().unwrap();

            let keys = queue.store.execute(None, |tran| {
                tran.list_keys(Queue::pending_scope())
            }).unwrap();
            assert_eq!(keys.len(), 10);

            for _ in 1..=10 {
                s.spawn(move || {
                    let queue = queue_store("queue_thread_workers");

                    while queue.pending_tasks_remaining().unwrap() > 0 {
                        if let Some((task_name, _))
                            = queue.claim_scheduled_pending_task().unwrap()
                        {
                            queue.finish_running_task(
                                &task_name
                            ).unwrap();
                        }

                        std::thread::sleep(
                            std::time::Duration::from_millis(5)
                        );
                    }
                });
            }
        });

        assert_eq!(queue.pending_tasks_remaining().unwrap(), 0);
        assert_eq!(queue.running_tasks_remaining().unwrap(), 0);
    }

    #[test]
    fn test_reschedule_long_running() {
        let queue = queue_store("test_reschedule_long_running");
        queue.store.wipe().unwrap();

        let name = const { Ident::make("job") };
        let value = Value::from("value");

        queue.schedule_task(
            name, &value, None, ScheduleMode::FinishOrReplaceExisting,
        ).unwrap();

        assert_eq!(queue.pending_tasks_remaining().unwrap(), 1);

        let job = queue.claim_scheduled_pending_task().unwrap();

        assert!(job.is_some());
        assert_eq!(queue.pending_tasks_remaining().unwrap(), 0);

        let job = queue.claim_scheduled_pending_task().unwrap();
        assert!(job.is_none());

        queue.reschedule_long_running_tasks(
            Some(Duration::from_secs(0))
        ).unwrap();

        assert_eq!(queue.pending_tasks_remaining().unwrap(), 1);
        assert!(queue.pending_task_scheduled(name).unwrap().is_some());

        let job = queue.claim_scheduled_pending_task().unwrap();

        assert!(job.is_some());
        assert_eq!(queue.pending_tasks_remaining().unwrap(), 0);
    }

    #[test]
    fn test_reschedule_finished_task() {
        let queue = queue_store("test_reschedule_finished_task");
        queue.store.wipe().unwrap();

        let name = const { Ident::make("task") };
        let value = Value::from("value");

        // Schedule the task
        queue.schedule_task(
            name, &value, None, ScheduleMode::FinishOrReplaceExisting,
        ).unwrap();
        assert_eq!(queue.pending_tasks_remaining().unwrap(), 1);

        // Get the task
        let _ = queue.claim_scheduled_pending_task().unwrap().unwrap();
        assert_eq!(queue.pending_tasks_remaining().unwrap(), 0);
        assert_eq!(queue.running_tasks_remaining().unwrap(), 1);

        // Finish the task and reschedule
        // queue.finish_running_task(task, Some(rescheduled)).unwrap();
        queue.schedule_task(
            name, &value,
            Some(Queue::now()),
            ScheduleMode::FinishOrReplaceExisting,
        ).unwrap();

        // There should now be a new pending task, and the
        // running task should be removed.
        assert_eq!(queue.pending_tasks_remaining().unwrap(), 1);
        assert_eq!(queue.running_tasks_remaining().unwrap(), 0);

        // Get and finish the pending task, but do not reschedule it
        let (key, _) = queue.claim_scheduled_pending_task().unwrap().unwrap();
        assert_eq!(queue.pending_tasks_remaining().unwrap(), 0);
        queue.finish_running_task(&key).unwrap();

        // There should not be a new pending task
        assert_eq!(queue.pending_tasks_remaining().unwrap(), 0);
    }

    #[test]
    fn test_schedule_with_existing_task() {
        let queue = queue_store("test_schedule_with_existing_task");
        queue.store.wipe().unwrap();

        let name = const { Ident::make("task") };
        let value_1 = Value::from("value_1");
        let value_2 = Value::from("value_2");

        let in_a_while = Queue::now() + 180;

        // Schedule a task, and then schedule again replacing the old
        {
            queue.schedule_task(
                name, &value_1.clone(),
                None, ScheduleMode::FinishOrReplaceExisting,
            ).unwrap();
            assert_eq!(queue.pending_tasks_remaining().unwrap(), 1);

            // Schedule again, replacing the existing task
            queue.schedule_task(
                name, &value_2.clone(), None,
                ScheduleMode::FinishOrReplaceExisting,
            ).unwrap();
            assert_eq!(queue.pending_tasks_remaining().unwrap(), 1);

            // We should have one task and the value should match the new task.
            let (key, task_value)
                = queue.claim_scheduled_pending_task().unwrap().unwrap();
            assert_eq!(task_value, value_2);

            assert_eq!(queue.running_tasks_remaining().unwrap(), 1);
            queue.finish_running_task(&key).unwrap();
        }

        // Schedule a task, and then schedule again keeping the old
        {
            queue.schedule_task(
                name, &value_1.clone(),
                None, ScheduleMode::FinishOrReplaceExisting,
            ).unwrap();
            queue.schedule_task(
                name, &value_2.clone(),
                Some(in_a_while), ScheduleMode::IfMissing,
            ).unwrap();

            // there should be only one task, it should not be rescheduled,
            // so we get get it and its value should match old.
            assert_eq!(queue.pending_tasks_remaining().unwrap(), 1);
            let (_, task_value)
                = queue.claim_scheduled_pending_task().unwrap().unwrap();
            assert_eq!(task_value, value_1);
        }

        // Schedule a task, and then schedule again rescheduling it
        {
            queue.schedule_task(
                name, &value_1.clone(),
                None, ScheduleMode::FinishOrReplaceExisting,
            ).unwrap();

            // we expect one pending task
            assert_eq!(queue.pending_tasks_remaining().unwrap(), 1);

            // reschedule that task to 3 minutes from now, keeping the
            // soonest value
            queue.schedule_task(
                name, &value_2.clone(),
                Some(in_a_while),
                ScheduleMode::FinishOrReplaceExistingSoonest,
            ).unwrap();

            // we still expect one pending task with the earlier
            // time and the new value.
            assert_eq!(queue.pending_tasks_remaining().unwrap(), 1);
            let (_, task_value)
                = queue.claim_scheduled_pending_task().unwrap().unwrap();
            assert_eq!(task_value, value_2);

            // But if we now schedule a task and then reschedule
            // it to 3 minutes from now NOT using the soonest. Then
            // we should see 1 pending task that we cannot claim
            // because it is not due.
            queue.schedule_task(
                name, &value_1.clone(),
                None,
                ScheduleMode::FinishOrReplaceExisting,
            ).unwrap();
            queue.schedule_task(
                name, &value_1.clone(),
                Some(in_a_while),
                ScheduleMode::FinishOrReplaceExisting,
            ).unwrap();

            assert_eq!(queue.pending_tasks_remaining().unwrap(), 1);
            assert!(queue.claim_scheduled_pending_task().unwrap().is_none());
        }

        // Schedule a task, claim it, and then finish and schedule a new task
        {
            // schedule a task
            queue.schedule_task(
                name, &value_1.clone(),
                None,
                ScheduleMode::FinishOrReplaceExisting,
            ).unwrap();

            // there should be 1 pending task, and 0 running
            assert_eq!(queue.pending_tasks_remaining().unwrap(), 1);
            assert_eq!(queue.running_tasks_remaining().unwrap(), 0);

            // claim the task
            let (_, task_value)
                = queue.claim_scheduled_pending_task().unwrap().unwrap();
            assert_eq!(task_value, value_1);
            assert_eq!(queue.pending_tasks_remaining().unwrap(), 0);
            assert_eq!(queue.running_tasks_remaining().unwrap(), 1);

            // schedule a new task
            queue.schedule_task(
                name, &value_2,
                None, ScheduleMode::FinishOrReplaceExisting,
            ).unwrap();

            // the running task should now be finished, and there should be
            // one new pending task
            assert_eq!(queue.running_tasks_remaining().unwrap(), 0);
            assert_eq!(queue.pending_tasks_remaining().unwrap(), 1);

            // claim the task, it should match the new task
            let (_, task_value)
                = queue.claim_scheduled_pending_task().unwrap().unwrap();
            assert_eq!(task_value, value_2);
        }
    }
}
