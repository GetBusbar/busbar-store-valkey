// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Whole-database test custody, shared by the logic and plugin test binaries.
//! Separate file handles take an exclusive OS lock, including across nextest processes.
//! Never unlink the lock file: waiters must continue locking the same inode.

use std::hash::{Hash, Hasher};

pub struct Database {
    client: redis::Client,

    _lock: std::fs::File,
}

impl Database {
    pub fn take(url: &str) -> Self {
        let client = redis::Client::open(url).expect("parse private test database");
        let info = client.get_connection_info();
        let shared = redis::Client::open(std::env::var("VALKEY_URL").expect("VALKEY_URL"))
            .expect("parse shared test database");
        assert_ne!(
            info.redis_settings().db(),
            shared.get_connection_info().redis_settings().db(),
            "refusing to FLUSHDB the shared database"
        );

        let mut hash = std::collections::hash_map::DefaultHasher::new();
        info.addr().to_string().hash(&mut hash);
        info.redis_settings().db().hash(&mut hash);
        let path =
            std::env::temp_dir().join(format!("busbar-valkey-db-{:016x}.lock", hash.finish()));
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(path)
            .expect("open database test lock");
        lock.lock().expect("lock private test database");
        let held = Self {
            client,
            _lock: lock,
        };
        held.flush().expect("empty private test database");
        held
    }

    pub fn connection(&self) -> redis::RedisResult<redis::Connection> {
        self.client.get_connection()
    }

    fn flush(&self) -> redis::RedisResult<()> {
        redis::cmd("FLUSHDB").query(&mut self.connection()?)
    }
}

impl Drop for Database {
    fn drop(&mut self) {
        if self.flush().is_err() {
            if std::thread::panicking() {
                eprintln!("private Valkey test database cleanup failed during unwind");
            } else {
                panic!("private Valkey test database cleanup failed");
            }
        }
    }
}
