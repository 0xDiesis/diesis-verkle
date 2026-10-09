//! Persistence and expiry checks for the optional RocksDB backend.
#![cfg(feature = "rocks_db")]

use rocksdb::{ColumnFamilyDescriptor, Options};
use std::{thread, time::Duration};
use verkle_db::{BareMetalDiskDb, BareMetalKVDb, BatchDB, BatchWriter, RocksDb};

#[test]
fn wrapper_batch_survives_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("wrapper");
    {
        let mut db = <RocksDb as BareMetalDiskDb>::from_path(&path);
        assert_eq!(db.fetch(b"missing"), None);
        let mut batch = <<RocksDb as BatchDB>::BatchWrite as BatchWriter>::new();
        batch.batch_put(b"first", b"old");
        batch.batch_put(b"second", b"retained");
        batch.batch_put(b"first", b"replacement");
        <RocksDb as BatchDB>::flush(&mut db, batch);
        assert_eq!(db.fetch(b"first"), Some(b"replacement".to_vec()));
    }
    let db = <RocksDb as BareMetalDiskDb>::from_path(&path);
    assert_eq!(db.fetch(b"first"), Some(b"replacement".to_vec()));
    assert_eq!(db.fetch(b"second"), Some(b"retained".to_vec()));
}

#[test]
fn multi_column_family_ttl_persists_then_expires_after_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ttl");
    let names = ["accounts", "storage"];
    let mut options = Options::default();
    options.create_if_missing(true);
    options.create_missing_column_families(true);
    let open = || {
        RocksDb::open_cf_descriptors_with_ttl(
            &options,
            &path,
            names
                .iter()
                .map(|name| ColumnFamilyDescriptor::new(*name, Options::default())),
            Duration::from_secs(1),
        )
        .unwrap()
    };
    {
        let db = open();
        for name in names {
            let cf = db.cf_handle(name).unwrap();
            db.put_cf(cf, b"key", name.as_bytes()).unwrap();
            db.flush_cf(cf).unwrap();
        }
    }
    let db = open();
    for name in names {
        let cf = db.cf_handle(name).unwrap();
        assert_eq!(
            db.get_cf(cf, b"key").unwrap(),
            Some(name.as_bytes().to_vec())
        );
    }
    // Native TTL timestamps use whole seconds and expiry is strict (>), so wait
    // past both boundaries before forcing compaction in each independent CF.
    thread::sleep(Duration::from_secs(3));
    for name in names {
        let cf = db.cf_handle(name).unwrap();
        db.compact_range_cf(cf, None::<&[u8]>, None::<&[u8]>);
        assert_eq!(
            db.get_cf(cf, b"key").unwrap(),
            None,
            "TTL failed for {name}"
        );
    }
    drop(db);
    let reopened = open();
    for name in names {
        assert_eq!(
            reopened
                .get_cf(reopened.cf_handle(name).unwrap(), b"key")
                .unwrap(),
            None,
            "expired key returned after reopening {name}"
        );
    }
}
