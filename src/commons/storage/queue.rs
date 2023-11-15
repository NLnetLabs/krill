use std::{
    borrow::Cow,
    convert::TryFrom,
    fmt::{Display, Formatter},
    str::FromStr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::commons::storage::{Key, KeyValueError, KeyValueStore, Scope, Segment, SegmentBuf, StorageResult};

use super::KeyValueStoreDispatcher;

const SEPARATOR: char = '-';

fn now() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time-travel is not supported")
        .as_millis()
}

struct TaskKey<'a> {
    pub name: Cow<'a, SegmentBuf>,
    pub timestamp_millis: u128,
}

impl<'a> TaskKey<'a> {
    fn key(&self) -> Key {
        Key::from_str(&format!("{}{}{}", self.timestamp_millis, SEPARATOR, self.name)).unwrap()
    }

    fn running_key(&self) -> Key {
        let mut key = self.key();
        key.add_super_scope(RunningTask::SEGMENT);
        key
    }

    fn pending_key(&self) -> Key {
        let mut key = self.key();
        key.add_super_scope(PendingTask::SEGMENT);
        key
    }
}

impl TryFrom<&Key> for TaskKey<'_> {
    type Error = KeyValueError;

    fn try_from(key: &Key) -> Result<Self, Self::Error> {
        let (ts, name) = key
            .name()
            .as_str()
            .split_once(SEPARATOR)
            .ok_or(KeyValueError::InvalidTaskKey(key.clone()))?;

        let name = Segment::parse(name)
            .map_err(|_| KeyValueError::InvalidTaskKey(key.clone()))?
            .to_owned();

        let timestamp_millis: u128 = ts.parse().map_err(|_| KeyValueError::InvalidTaskKey(key.clone()))?;

        Ok(TaskKey {
            name: Cow::Owned(name),
            timestamp_millis,
        })
    }
}

impl From<&PendingTask> for Key {
    fn from(p: &PendingTask) -> Self {
        let mut key = Key::from_str(&p.to_string()).unwrap();
        key.add_super_scope(PendingTask::SEGMENT);
        key
    }
}

impl From<&RunningTask> for Key {
    fn from(p: &RunningTask) -> Self {
        let mut key = Key::from_str(&p.to_string()).unwrap();
        key.add_super_scope(RunningTask::SEGMENT);
        key
    }
}

#[derive(Clone, Debug)]
pub struct PendingTask {
    pub name: SegmentBuf,
    pub timestamp_millis: u128,
    pub value: serde_json::Value,
}

impl PendingTask {
    const SEGMENT: &Segment = unsafe { Segment::from_str_unchecked("pending") };
}

impl PartialEq for PendingTask {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
    }
}

impl Display for PendingTask {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}{}{}",
            self.timestamp_millis,
            SEPARATOR.encode_utf8(&mut [0; 4]),
            self.name,
        )
    }
}

#[derive(Clone, Debug)]
pub struct RunningTask {
    pub name: SegmentBuf,
    pub timestamp_millis: u128,
    pub value: serde_json::Value,
}

impl RunningTask {
    const SEGMENT: &Segment = unsafe { Segment::from_str_unchecked("running") };
}

impl Display for RunningTask {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}{}{}",
            self.timestamp_millis,
            SEPARATOR.encode_utf8(&mut [0; 4]),
            self.name,
        )
    }
}

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

pub trait Queue {
    const RESCHEDULE_AFTER: Duration = Duration::from_secs(15 * 60);

    fn lock_scope() -> Scope {
        Scope::global()
    }

    fn pending_scope() -> Scope {
        Scope::from_segment(PendingTask::SEGMENT)
    }

    fn running_scope() -> Scope {
        Scope::from_segment(RunningTask::SEGMENT)
    }

    /// Returns the number of pending tasks remaining
    fn pending_tasks_remaining(&self) -> StorageResult<usize>;

    /// Returns the number of running tasks
    fn running_tasks_remaining(&self) -> StorageResult<usize>;

    /// Returns the currently running tasks
    fn running_tasks_keys(&self) -> StorageResult<Vec<Key>>;

    /// Schedule a task.
    fn schedule_task(
        &self,
        name: SegmentBuf,
        value: serde_json::Value,
        timestamp_millis: Option<u128>,
        existing: ScheduleMode,
    ) -> StorageResult<()>;

    /// Returns the scheduled timestamp in ms for the named task, if any.
    fn pending_task_scheduled(&self, name: SegmentBuf) -> StorageResult<Option<u128>>;

    /// Marks a running task as finished. Fails if the task is not running.
    fn finish_running_task(&self, running: &Key) -> StorageResult<()>;

    /// Reschedules a running task as pending. Fails if the task is not running.
    fn reschedule_running_task(&self, running: &Key, timestamp_millis: Option<u128>) -> StorageResult<()>;

    /// Claims the next scheduled pending task, if any.
    fn claim_scheduled_pending_task(&self) -> StorageResult<Option<RunningTask>>;

    /// Reschedules running tasks that have timed out.
    fn reschedule_long_running_tasks(&self, reschedule_after: Option<&Duration>) -> StorageResult<()>;
}

impl Queue for KeyValueStore {
    fn pending_tasks_remaining(&self) -> StorageResult<usize> {
        self.execute(&Self::lock_scope(), |kv| {
            kv.list_keys(&Self::pending_scope()).map(|list| list.len())
        })
    }

    fn running_tasks_remaining(&self) -> StorageResult<usize> {
        self.execute(&Self::lock_scope(), |kv| {
            kv.list_keys(&Self::running_scope()).map(|list| list.len())
        })
    }

    fn running_tasks_keys(&self) -> StorageResult<Vec<Key>> {
        self.execute(&Self::lock_scope(), |kv| kv.list_keys(&Self::running_scope()))
    }

    fn schedule_task(
        &self,
        name: SegmentBuf,
        value: serde_json::Value,
        timestamp_millis: Option<u128>,
        mode: ScheduleMode,
    ) -> StorageResult<()> {
        let mut new_task = PendingTask {
            name,
            timestamp_millis: timestamp_millis.unwrap_or(now()),
            value,
        };
        let new_task_key = Key::from(&new_task);

        self.execute(&Self::lock_scope(), |s: &KeyValueStoreDispatcher| {
            let running_key_opt = s
                .list_keys(&Self::running_scope())?
                .into_iter()
                .filter_map(|k| TaskKey::try_from(&k).ok())
                .find(|running| running.name.as_ref() == &new_task.name)
                .map(|tk| tk.running_key());

            let pending_key_opt = s
                .list_keys(&Self::pending_scope())?
                .into_iter()
                .filter_map(|k| TaskKey::try_from(&k).ok())
                .find(|p| p.name.as_ref() == &new_task.name)
                .map(|tk| tk.pending_key());

            match mode {
                ScheduleMode::IfMissing => {
                    if pending_key_opt.is_some() || running_key_opt.is_some() {
                        // nothing to do, there is something
                        Ok(())
                    } else {
                        // no pending or running task exists, just add the new task
                        s.store(&new_task_key, new_task.value.clone())
                    }
                }
                ScheduleMode::ReplaceExisting => {
                    if let Some(pending) = pending_key_opt {
                        s.delete(&pending)?;
                    }
                    s.store(&new_task_key, new_task.value.clone())
                }
                ScheduleMode::ReplaceExistingSoonest => {
                    if let Some(pending) = pending_key_opt {
                        if let Ok(tk) = TaskKey::try_from(&pending) {
                            new_task.timestamp_millis = new_task.timestamp_millis.min(tk.timestamp_millis);
                        }
                        s.delete(&pending)?;
                    }

                    let new_task_key = Key::from(&new_task);
                    s.store(&new_task_key, new_task.value.clone())
                }
                ScheduleMode::FinishOrReplaceExisting => {
                    if let Some(running) = running_key_opt {
                        s.delete(&running)?;
                    }
                    if let Some(pending) = pending_key_opt {
                        s.delete(&pending)?;
                    }
                    s.store(&new_task_key, new_task.value.clone())
                }
                ScheduleMode::FinishOrReplaceExistingSoonest => {
                    if let Some(running) = running_key_opt {
                        s.delete(&running)?;
                    }

                    if let Some(pending) = pending_key_opt {
                        if let Ok(tk) = TaskKey::try_from(&pending) {
                            new_task.timestamp_millis = new_task.timestamp_millis.min(tk.timestamp_millis);
                        }
                        s.delete(&pending)?;
                    }

                    let new_task_key = Key::from(&new_task);
                    s.store(&new_task_key, new_task.value.clone())
                }
            }
        })
    }

    fn finish_running_task(&self, running_key: &Key) -> StorageResult<()> {
        self.execute(&Self::lock_scope(), |kv| {
            if kv.has(running_key)? {
                kv.delete(running_key)
            } else {
                Err(KeyValueError::Other(format!(
                    "Cannot finish task {}. It is not running.",
                    running_key
                )))
            }
        })
    }

    fn reschedule_running_task(&self, running: &Key, timestamp_millis: Option<u128>) -> StorageResult<()> {
        let pending_key = {
            let mut task_key = TaskKey::try_from(running)?;
            task_key.timestamp_millis = timestamp_millis.unwrap_or_else(now);

            task_key.pending_key()
        };

        self.execute(&Self::lock_scope(), |kv| kv.move_value(running, &pending_key))
    }

    fn claim_scheduled_pending_task(&self) -> StorageResult<Option<RunningTask>> {
        self.execute(&Self::lock_scope(), |kv| {
            let tasks_before = now();

            if let Some(pending) = kv
                .list_keys(&Self::pending_scope())?
                .into_iter()
                .filter_map(|k| TaskKey::try_from(&k).ok())
                .filter(|tk| tk.timestamp_millis <= tasks_before)
                .min_by_key(|tk| tk.timestamp_millis)
            {
                let pending_key = pending.pending_key();

                if let Some(value) = kv.get(&pending_key)? {
                    let mut running_task = RunningTask {
                        name: pending.name.into_owned(),
                        timestamp_millis: tasks_before,
                        value,
                    };
                    let mut running_key = Key::from(&running_task);

                    if kv.has(&running_key)? {
                        // It's not pretty to sleep blocking, even if it's
                        // for 1 ms, but if we don't then get a name collision
                        // with an existing running task.
                        std::thread::sleep(Duration::from_millis(1));
                        running_task.timestamp_millis = now();
                        running_key = Key::from(&running_task);
                    }

                    kv.move_value(&pending_key, &running_key)?;

                    Ok(Some(running_task))
                } else {
                    Ok(None)
                }
            } else {
                Ok(None)
            }
        })
    }

    fn reschedule_long_running_tasks(&self, reschedule_after: Option<&Duration>) -> StorageResult<()> {
        let now = now();

        let reschedule_after = reschedule_after.unwrap_or(&KeyValueStore::RESCHEDULE_AFTER);
        let reschedule_timeout = now - reschedule_after.as_millis();

        self.execute(&Self::lock_scope(), |s: &KeyValueStoreDispatcher| {
            s.list_keys(&Self::running_scope())?
                .into_iter()
                .filter_map(|k| {
                    let task = TaskKey::try_from(&k).ok()?;
                    if task.timestamp_millis <= reschedule_timeout {
                        Some(task)
                    } else {
                        None
                    }
                })
                .for_each(|tk| {
                    let running_key = tk.running_key();

                    let pending_key = TaskKey {
                        name: Cow::Borrowed(&tk.name),
                        timestamp_millis: now,
                    }
                    .pending_key();

                    let _ = s.move_value(&running_key, &pending_key);
                });

            Ok(())
        })
    }

    fn pending_task_scheduled(&self, name: SegmentBuf) -> StorageResult<Option<u128>> {
        self.execute(&Self::lock_scope(), |kv| {
            kv.list_keys(&Self::pending_scope()).map(|keys| {
                keys.into_iter()
                    .filter_map(|k| TaskKey::try_from(&k).ok())
                    .find(|p| p.name.as_ref() == &name)
                    .map(|p| p.timestamp_millis)
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use std::{thread, time::Duration};

    use serde_json::Value;

    use super::{PendingTask, Queue};
    use crate::commons::storage::{
        queue::{now, ScheduleMode},
        Key, KeyValueStore, Namespace, Scope, Segment, SegmentBuf,
    };

    fn queue_store(ns: &str) -> KeyValueStore {
        let storage_url = crate::test::mem_storage();

        KeyValueStore::create(&storage_url, Namespace::parse(ns).unwrap()).unwrap()
    }

    #[test]
    fn queue_thread_workers() {
        let queue = queue_store("test_queue");
        queue.wipe().unwrap();

        thread::scope(|s| {
            let create = s.spawn(|| {
                for i in 1..=10 {
                    let name = &format!("job-{i}");
                    let segment = Segment::parse(name).unwrap();
                    let value = Value::from("value");

                    queue
                        .schedule_task(segment.into(), value, None, ScheduleMode::FinishOrReplaceExisting)
                        .unwrap();
                    println!("> Scheduled job {}", &name);
                }
            });

            create.join().unwrap();
            let keys = queue.list_keys(&Scope::from_segment(PendingTask::SEGMENT)).unwrap();
            assert_eq!(keys.len(), 10);

            for _i in 1..=10 {
                s.spawn(|| {
                    while queue.pending_tasks_remaining().unwrap() > 0 {
                        if let Some(running_task) = queue.claim_scheduled_pending_task().unwrap() {
                            queue.finish_running_task(&Key::from(&running_task)).unwrap();
                        }

                        std::thread::sleep(std::time::Duration::from_millis(5));
                    }
                });
            }
        });

        let pending = queue.pending_tasks_remaining().unwrap();
        assert_eq!(pending, 0);

        let running = queue.running_tasks_remaining().unwrap();
        assert_eq!(running, 0);
    }

    #[test]
    fn test_reschedule_long_running() {
        let queue = queue_store("test_cleanup_queue");
        queue.wipe().unwrap();

        let name = "job";
        let segment = Segment::parse(name).unwrap();
        let value = Value::from("value");

        queue
            .schedule_task(segment.into(), value, None, ScheduleMode::FinishOrReplaceExisting)
            .unwrap();

        assert_eq!(queue.pending_tasks_remaining().unwrap(), 1);

        let job = queue.claim_scheduled_pending_task().unwrap();

        assert!(job.is_some());
        assert_eq!(queue.pending_tasks_remaining().unwrap(), 0);

        let job = queue.claim_scheduled_pending_task().unwrap();

        assert!(job.is_none());

        queue
            .reschedule_long_running_tasks(Some(&Duration::from_secs(0)))
            .unwrap();

        let existing = queue.pending_task_scheduled(segment.into()).unwrap();

        assert!(existing.is_some());
        assert_eq!(queue.pending_tasks_remaining().unwrap(), 1);

        let job = queue.claim_scheduled_pending_task().unwrap();

        assert!(job.is_some());
        assert_eq!(queue.pending_tasks_remaining().unwrap(), 0);
    }

    #[test]
    fn test_reschedule_finished_task() {
        let queue = queue_store("test_cleanup_queue");
        queue.wipe().unwrap();

        let name = "task";
        let segment = Segment::parse(name).unwrap();
        let value = Value::from("value");

        // Schedule the task
        queue
            .schedule_task(segment.into(), value, None, ScheduleMode::FinishOrReplaceExisting)
            .unwrap();
        assert_eq!(queue.pending_tasks_remaining().unwrap(), 1);

        // Get the task
        let running_task = queue.claim_scheduled_pending_task().unwrap().unwrap();
        assert_eq!(queue.pending_tasks_remaining().unwrap(), 0);
        assert_eq!(queue.running_tasks_remaining().unwrap(), 1);

        // Finish the task and reschedule
        // queue.finish_running_task(task, Some(rescheduled)).unwrap();
        queue
            .schedule_task(
                running_task.name,
                running_task.value,
                Some(now()),
                ScheduleMode::FinishOrReplaceExisting,
            )
            .unwrap();

        // There should now be a new pending task, and the
        // running task should be removed.
        assert_eq!(queue.pending_tasks_remaining().unwrap(), 1);
        assert_eq!(queue.running_tasks_remaining().unwrap(), 0);

        // Get and finish the pending task, but do not reschedule it
        let running_task = queue.claim_scheduled_pending_task().unwrap().unwrap();
        assert_eq!(queue.pending_tasks_remaining().unwrap(), 0);
        queue.finish_running_task(&Key::from(&running_task)).unwrap();

        // There should not be a new pending task
        assert_eq!(queue.pending_tasks_remaining().unwrap(), 0);
    }

    #[test]
    fn test_schedule_with_existing_task() {
        let queue = queue_store("test_cleanup_queue");
        queue.wipe().unwrap();

        let name: SegmentBuf = SegmentBuf::parse_lossy("task");
        let value_1 = Value::from("value_1");
        let value_2 = Value::from("value_2");

        let in_a_while = now() + 180;

        // Schedule a task, and then schedule again replacing the old
        {
            queue
                .schedule_task(
                    name.clone(),
                    value_1.clone(),
                    None,
                    ScheduleMode::FinishOrReplaceExisting,
                )
                .unwrap();
            assert_eq!(queue.pending_tasks_remaining().unwrap(), 1);

            // Schedule again, replacing the existing task
            queue
                .schedule_task(
                    name.clone(),
                    value_2.clone(),
                    None,
                    ScheduleMode::FinishOrReplaceExisting,
                )
                .unwrap();
            assert_eq!(queue.pending_tasks_remaining().unwrap(), 1);

            // We should have one task and the value should match the new task.
            let task = queue.claim_scheduled_pending_task().unwrap().unwrap();
            assert_eq!(task.value, value_2);

            assert_eq!(queue.running_tasks_remaining().unwrap(), 1);
            queue.finish_running_task(&Key::from(&task)).unwrap();
        }

        // Schedule a task, and then schedule again keeping the old
        {
            queue
                .schedule_task(
                    name.clone(),
                    value_1.clone(),
                    None,
                    ScheduleMode::FinishOrReplaceExisting,
                )
                .unwrap();
            queue
                .schedule_task(name.clone(), value_2.clone(), Some(in_a_while), ScheduleMode::IfMissing)
                .unwrap();

            // there should be only one task, it should not be rescheduled,
            // so we get get it and its value should match old.
            assert_eq!(queue.pending_tasks_remaining().unwrap(), 1);
            let task = queue.claim_scheduled_pending_task().unwrap().unwrap();
            assert_eq!(task.value, value_1);
        }

        // Schedule a task, and then schedule again rescheduling it
        {
            queue
                .schedule_task(
                    name.clone(),
                    value_1.clone(),
                    None,
                    ScheduleMode::FinishOrReplaceExisting,
                )
                .unwrap();

            // we expect one pending task
            assert_eq!(queue.pending_tasks_remaining().unwrap(), 1);

            // reschedule that task to 3 minutes from now, keeping the
            // soonest value
            queue
                .schedule_task(
                    name.clone(),
                    value_2.clone(),
                    Some(in_a_while),
                    ScheduleMode::FinishOrReplaceExistingSoonest,
                )
                .unwrap();

            // we still expect one pending task with the earlier
            // time and the new value.
            assert_eq!(queue.pending_tasks_remaining().unwrap(), 1);
            let task = queue.claim_scheduled_pending_task().unwrap().unwrap();
            assert_eq!(task.value, value_2);

            // But if we now schedule a task and then reschedule
            // it to 3 minutes from now NOT using the soonest. Then
            // we should see 1 pending task that we cannot claim
            // because it is not due.
            queue
                .schedule_task(
                    name.clone(),
                    value_1.clone(),
                    None,
                    ScheduleMode::FinishOrReplaceExisting,
                )
                .unwrap();
            queue
                .schedule_task(
                    name.clone(),
                    value_1.clone(),
                    Some(in_a_while),
                    ScheduleMode::FinishOrReplaceExisting,
                )
                .unwrap();

            assert_eq!(queue.pending_tasks_remaining().unwrap(), 1);
            assert!(queue.claim_scheduled_pending_task().unwrap().is_none());
        }

        // Schedule a task, claim it, and then finish and schedule a new task
        {
            // schedule a task
            queue
                .schedule_task(
                    name.clone(),
                    value_1.clone(),
                    None,
                    ScheduleMode::FinishOrReplaceExisting,
                )
                .unwrap();

            // there should be 1 pending task, and 0 running
            assert_eq!(queue.pending_tasks_remaining().unwrap(), 1);
            assert_eq!(queue.running_tasks_remaining().unwrap(), 0);

            // claim the task
            let task = queue.claim_scheduled_pending_task().unwrap().unwrap();
            assert_eq!(task.value, value_1);
            assert_eq!(queue.pending_tasks_remaining().unwrap(), 0);
            assert_eq!(queue.running_tasks_remaining().unwrap(), 1);

            // schedule a new task
            queue
                .schedule_task(
                    name.clone(),
                    value_2.clone(),
                    None,
                    ScheduleMode::FinishOrReplaceExisting,
                )
                .unwrap();

            // the running task should now be finished, and there should be 1 new pending task
            assert_eq!(queue.running_tasks_remaining().unwrap(), 0);
            assert_eq!(queue.pending_tasks_remaining().unwrap(), 1);

            // claim the task, it should match the new task
            let task = queue.claim_scheduled_pending_task().unwrap().unwrap();
            assert_eq!(task.value, value_2);
        }
    }
}
