//! Test-only helpers. Compiled out of release builds.

/// Set an environment variable for the duration of a test and restore the
/// previous value on drop. Env mutation is process-global, so all users
/// share one lock — env-touching tests serialize on it.
pub struct EnvGuard {
    key: &'static str,
    previous: Option<String>,
    _lock: std::sync::MutexGuard<'static, ()>,
}

static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

impl EnvGuard {
    pub fn set(key: &'static str, value: &str) -> Self {
        let lock = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let previous = std::env::var(key).ok();
        std::env::set_var(key, value);
        Self {
            key,
            previous,
            _lock: lock,
        }
    }

    /// Ensure the variable is unset for the duration of the test.
    pub fn unset(key: &'static str) -> Self {
        let lock = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let previous = std::env::var(key).ok();
        std::env::remove_var(key);
        Self {
            key,
            previous,
            _lock: lock,
        }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        match &self.previous {
            Some(v) => std::env::set_var(self.key, v),
            None => std::env::remove_var(self.key),
        }
    }
}
