// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

/// A disposable database that drops itself on drop, panic path included. Written as a trailing
/// statement, the cleanup only ran when the test passed, so every red run leaked a fully migrated
/// database under a pid+nanos name that nothing would ever reclaim.
pub(crate) struct TempDb {
    admin_url: String,
    name: String,
}

impl TempDb {
    pub(crate) fn create(admin_url: &str, prefix: &str) -> Self {
        let name = format!(
            "{prefix}_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let mut maint = postgres::Client::connect(admin_url, postgres::NoTls)
            .expect("connect to create the disposable database");
        let _ = maint.execute(&format!("DROP DATABASE IF EXISTS {name}"), &[]);
        maint
            .execute(&format!("CREATE DATABASE {name}"), &[])
            .expect("the boot proof needs its own empty database");
        Self {
            admin_url: admin_url.to_string(),
            name,
        }
    }

    /// Rewrite the admin DSN to name this database, keeping the credentials. The shape is the one
    /// this crate's own fixtures and `dsn_password` already assume.
    pub(crate) fn url(&self) -> String {
        let rest = self
            .admin_url
            .split("://")
            .nth(1)
            .expect("url must have a scheme");
        let (userinfo, host_and_db) = rest.rsplit_once('@').expect("url must have userinfo");
        let (host_port, _) = host_and_db
            .split_once('/')
            .expect("url must have a db path");
        format!("postgres://{userinfo}@{host_port}/{}", self.name)
    }
}

impl Drop for TempDb {
    fn drop(&mut self) {
        if let Ok(mut maint) = postgres::Client::connect(&self.admin_url, postgres::NoTls) {
            let _ = maint.execute(
                &format!("DROP DATABASE IF EXISTS {} WITH (FORCE)", self.name),
                &[],
            );
        }
    }
}
