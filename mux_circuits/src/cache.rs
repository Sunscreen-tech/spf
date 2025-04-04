use std::{marker::PhantomData, path::PathBuf};

use cached::IOCached;
use serde::{de::DeserializeOwned, Serialize};

pub struct FileCache<K, V> {
    prefix: String,
    _phantom: PhantomData<(K, V)>,
}

impl<K, V> FileCache<K, V> {
    pub fn new(prefix: &str) -> Self {
        Self {
            prefix: prefix.to_owned(),
            _phantom: PhantomData,
        }
    }

    fn get_dir(&self) -> Result<PathBuf, std::io::Error> {
        let cache_dir = PathBuf::from(".circuit_cache");

        if !std::path::Path::exists(&cache_dir) {
            std::fs::create_dir(&cache_dir)?;
        }

        let entry_dir = cache_dir.join(&self.prefix);

        if !std::path::Path::exists(&entry_dir) {
            std::fs::create_dir(&entry_dir)?;
        }

        Ok(entry_dir)
    }
}

impl<K, V> IOCached<K, V> for FileCache<K, V>
where
    K: ToString,
    V: Serialize + DeserializeOwned,
{
    type Error = std::io::Error;

    fn cache_get(&self, k: &K) -> Result<Option<V>, Self::Error> {
        let dir = self.get_dir()?;

        let file_name = dir.join(k.to_string().chars().take(32).collect::<String>());

        if std::path::Path::exists(&file_name) {
            let data = std::fs::read(file_name)?;

            Ok(Some(bincode::deserialize(&data).unwrap()))
        } else {
            Ok(None)
        }
    }

    fn cache_lifespan(&self) -> Option<u64> {
        None
    }

    fn cache_remove(&self, k: &K) -> Result<Option<V>, Self::Error> {
        let dir = self.get_dir()?;

        let file_name = dir.join(k.to_string().chars().take(32).collect::<String>());

        std::fs::remove_file(&file_name)?;

        Ok(None)
    }

    fn cache_set(&self, k: K, v: V) -> Result<Option<V>, Self::Error> {
        let dir = self.get_dir()?;

        let file_name = dir.join(k.to_string().chars().take(32).collect::<String>());

        std::fs::write(&file_name, bincode::serialize(&v).unwrap())?;

        Ok(Some(v))
    }

    fn cache_set_lifespan(&mut self, _seconds: u64) -> Option<u64> {
        None
    }

    fn cache_set_refresh(&mut self, _refresh: bool) -> bool {
        false
    }

    fn cache_unset_lifespan(&mut self) -> Option<u64> {
        None
    }
}
