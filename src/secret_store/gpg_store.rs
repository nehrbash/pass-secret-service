use std::{
    collections::HashMap,
    fmt::Debug,
    fs::Metadata,
    io::{self, ErrorKind},
    path::{Path, PathBuf},
    sync::Arc,
    time::SystemTime,
};

use async_trait::async_trait;
use futures_util::{stream, StreamExt};
use nanoid::nanoid;
use serde::{Deserialize, Serialize};
use tokio::{fs, io::AsyncWriteExt, sync::RwLock};

use crate::{
    error::Result,
    pass::PasswordStore,
    secret_store::{slugify, SecretStore, NANOID_ALPHABET, PASS_SUBDIR},
};

const LABEL_FILE: &str = ".label";
const META_DIR: &str = ".meta";
const ALIASES_DIR: &str = ".aliases";
const SEARCH_CONCURRENCY: usize = 8;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Meta {
    label: String,
    attributes: HashMap<String, String>,
}

type Cache = Arc<RwLock<HashMap<(String, String), (SystemTime, Meta)>>>;

/// Secret store where labels and attributes live in GPG-encrypted `.meta/<id>.gpg` files.
#[derive(Debug, Clone)]
pub struct GpgSecretStore<'a> {
    pass: &'a PasswordStore,
    cache: Cache,
}

/// Collection ids and aliases become path components and, for collections, D-Bus object
/// path elements, so only slug characters are allowed.
fn is_slug(name: &str) -> bool {
    !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

fn alias_path(alias: &str) -> Result<PathBuf> {
    if !is_slug(alias) {
        return Err(io::Error::from(ErrorKind::InvalidInput).into());
    }
    Ok(Path::new(PASS_SUBDIR).join(ALIASES_DIR).join(alias))
}

impl<'a> GpgSecretStore<'a> {
    fn collection_path(collection: &str) -> PathBuf {
        Path::new(PASS_SUBDIR).join(collection)
    }

    fn meta_path(collection: &str, secret: &str) -> PathBuf {
        Self::collection_path(collection)
            .join(META_DIR)
            .join(secret)
    }

    /// the on-disk `.gpg` file for a password path
    fn gpg_file(&self, path: &Path) -> PathBuf {
        let mut file = self.pass.directory.join(path).into_os_string();
        file.push(".gpg");
        file.into()
    }

    async fn read_text(&self, path: impl AsRef<Path>) -> Result<String> {
        Ok(fs::read_to_string(self.pass.directory.join(path))
            .await?
            .trim()
            .to_owned())
    }

    /// write through a temporary file and rename, so readers never see a partial file
    async fn write_text(&self, path: impl AsRef<Path>, text: &str) -> Result {
        let path = path.as_ref();
        let mut temp = path.as_os_str().to_owned();
        temp.push(".tmp");
        let mut file = self.pass.open_file(&temp).await?;
        file.set_len(0).await?;
        file.write_all(text.as_bytes()).await?;
        file.sync_all().await?;
        fs::rename(
            self.pass.directory.join(&temp),
            self.pass.directory.join(path),
        )
        .await?;
        Ok(())
    }

    async fn collection_exists(&self, collection: &str) -> Result<()> {
        fs::metadata(self.pass.directory.join(Self::collection_path(collection))).await?;
        Ok(())
    }

    /// load a secret's metadata, decrypting only when the file changed since it was cached
    async fn meta(&self, collection: &str, secret: &str, can_prompt: bool) -> Result<Meta> {
        let path = Self::meta_path(collection, secret);
        let mtime = fs::metadata(self.gpg_file(&path)).await?.modified()?;
        let key = (collection.to_owned(), secret.to_owned());

        if let Some((cached_at, meta)) = self.cache.read().await.get(&key) {
            if *cached_at == mtime {
                return Ok(meta.clone());
            }
        }

        let plain = self.pass.read_password(&path, can_prompt).await?;
        let meta: Meta = serde_json::from_slice(&plain).map_err(io::Error::from)?;
        self.cache.write().await.insert(key, (mtime, meta.clone()));
        Ok(meta)
    }

    async fn write_meta(&self, collection: &str, secret: &str, meta: Meta) -> Result {
        let path = Self::meta_path(collection, secret);
        let json = serde_json::to_vec(&meta).map_err(io::Error::from)?;
        self.pass.write_password(&path, json).await?;
        let mtime = fs::metadata(self.gpg_file(&path)).await?.modified()?;
        self.cache
            .write()
            .await
            .insert((collection.to_owned(), secret.to_owned()), (mtime, meta));
        Ok(())
    }

    /// read-modify-write may prompt: the caller is changing the secret, so a pinentry is expected
    async fn update_meta(
        &self,
        collection: &str,
        secret: &str,
        update: impl FnOnce(&mut Meta),
    ) -> Result {
        let mut meta = self.meta(collection, secret, true).await?;
        update(&mut meta);
        self.write_meta(collection, secret, meta).await
    }

    async fn list_aliases(&self) -> Result<Vec<(String, String)>> {
        let mut aliases = vec![];
        let dir = Path::new(PASS_SUBDIR).join(ALIASES_DIR);
        for (file_type, name) in self.pass.list_items(&dir).await? {
            if file_type.is_file() && is_slug(&name) {
                let target = self.read_text(dir.join(&name)).await?;
                aliases.push((name, target));
            }
        }
        Ok(aliases)
    }
}

#[async_trait]
impl<'a> SecretStore<'a> for GpgSecretStore<'a> {
    async fn new(pass: &'a PasswordStore) -> Result<Self> {
        pass.make_dir(PASS_SUBDIR).await?;
        Ok(Self {
            pass,
            cache: Cache::default(),
        })
    }

    fn get_pass(&self) -> &'a PasswordStore {
        self.pass
    }

    async fn get_label(&self, collection: Arc<String>) -> Result<String> {
        self.read_text(Self::collection_path(&collection).join(LABEL_FILE))
            .await
    }

    async fn set_label(&self, collection: Arc<String>, label: String) -> Result {
        self.write_text(Self::collection_path(&collection).join(LABEL_FILE), &label)
            .await
    }

    async fn list_all_aliases(&self) -> Result<HashMap<String, Vec<String>>> {
        let mut map: HashMap<String, Vec<String>> = HashMap::new();
        for (alias, target) in self.list_aliases().await? {
            map.entry(target).or_default().push(alias);
        }
        Ok(map)
    }

    async fn list_aliases_for_collection(&self, collection: Arc<String>) -> Result<Vec<String>> {
        Ok(self
            .list_aliases()
            .await?
            .into_iter()
            .filter(|(_, target)| *target == *collection)
            .map(|(alias, _)| alias)
            .collect())
    }

    async fn get_alias(&self, alias: Arc<String>) -> Result<String> {
        self.read_text(alias_path(&alias)?).await
    }

    async fn set_alias(&self, alias: Arc<String>, collection: Option<String>) -> Result {
        let path = alias_path(&alias)?;
        match collection {
            Some(target) => self.write_text(path, &target).await,
            None => match fs::remove_file(self.pass.directory.join(path)).await {
                Err(e) if e.kind() != ErrorKind::NotFound => Err(e.into()),
                _ => Ok(()),
            },
        }
    }

    async fn collections(&self) -> Vec<String> {
        let items = self.pass.list_items(PASS_SUBDIR).await.unwrap_or_default();
        items
            .into_iter()
            .filter(|(file_type, name)| file_type.is_dir() && !name.starts_with('.'))
            .map(|(_, name)| name)
            .collect()
    }

    async fn create_collection(
        &self,
        label: Option<String>,
        alias: Option<String>,
    ) -> Result<String> {
        let had_provided_label = label.is_some();
        let label = label.unwrap_or_else(|| "Untitled Collection".into());

        // an existing alias returns its collection instead of creating a new one
        if let Some(id) = match &alias {
            Some(alias) => self.get_alias(Arc::new(alias.clone())).await.ok(),
            None => None,
        } {
            let has_label = self.get_label(Arc::new(id.clone())).await.is_ok();
            if had_provided_label || !has_label {
                self.set_label(Arc::new(id.clone()), label).await?;
            }
            return Ok(id);
        }

        let slug = slugify(&label);
        let taken = !is_slug(&slug)
            || fs::try_exists(self.pass.directory.join(Self::collection_path(&slug))).await?;
        let id = if taken {
            format!("{}_{}", slug, nanoid!(4, &NANOID_ALPHABET))
        } else {
            slug
        };

        self.pass.make_dir(Self::collection_path(&id)).await?;
        self.set_label(Arc::new(id.clone()), label).await?;
        if let Some(alias) = alias {
            self.set_alias(Arc::new(alias), Some(id.clone())).await?;
        }
        Ok(id)
    }

    async fn delete_collection(&self, collection_id: Arc<String>) -> Result {
        self.pass
            .remove_dir(Self::collection_path(&collection_id))
            .await?;
        self.cache
            .write()
            .await
            .retain(|(collection, _), _| *collection != *collection_id);
        for alias in self.list_aliases_for_collection(collection_id).await? {
            self.set_alias(Arc::new(alias), None).await?;
        }
        Ok(())
    }

    async fn search_all_collections(
        &self,
        attributes: HashMap<String, String>,
    ) -> Result<HashMap<String, Vec<String>>> {
        let attributes = Arc::new(attributes);
        let mut results = HashMap::new();
        for id in self.collections().await {
            let found = self
                .search_collection(Arc::new(id.clone()), attributes.clone())
                .await?;
            results.insert(id, found);
        }
        Ok(results)
    }

    async fn search_collection(
        &self,
        collection_id: Arc<String>,
        attributes: Arc<HashMap<String, String>>,
    ) -> Result<Vec<String>> {
        if attributes.is_empty() {
            return Ok(vec![]);
        }
        self.collection_exists(&collection_id).await?;

        let secrets = self.list_secrets(&collection_id).await?;
        let matches = stream::iter(secrets)
            .map(|secret| {
                let collection_id = &collection_id;
                let attributes = &attributes;
                async move {
                    match self.meta(collection_id, &secret, false).await {
                        Ok(meta) => attributes
                            .iter()
                            .all(|(k, v)| meta.attributes.get(k) == Some(v))
                            .then_some(secret),
                        Err(e) => {
                            log::warn!("skipping {collection_id}/{secret} in search: {e}");
                            None
                        }
                    }
                }
            })
            .buffer_unordered(SEARCH_CONCURRENCY)
            .filter_map(|found| async move { found })
            .collect()
            .await;
        Ok(matches)
    }

    async fn stat_collection(&self, collection_id: &str) -> Result<Metadata> {
        Ok(fs::metadata(
            self.pass
                .directory
                .join(Self::collection_path(collection_id)),
        )
        .await?)
    }

    async fn list_secrets(&self, collection_id: &str) -> Result<Vec<String>> {
        Ok(self
            .pass
            .list_items(Self::collection_path(collection_id))
            .await?
            .into_iter()
            .filter_map(|(file_type, name)| {
                let id = name.strip_suffix(".gpg")?;
                file_type.is_file().then(|| id.to_owned())
            })
            .collect())
    }

    async fn read_secret(
        &self,
        collection_id: &str,
        secret_id: &str,
        can_prompt: bool,
    ) -> Result<Vec<u8>> {
        self.pass
            .read_password(
                Self::collection_path(collection_id).join(secret_id),
                can_prompt,
            )
            .await
    }

    async fn read_secret_attrs(
        &self,
        collection: Arc<String>,
        secret: Arc<String>,
    ) -> Result<HashMap<String, String>> {
        Ok(self.meta(&collection, &secret, false).await?.attributes)
    }

    async fn delete_secret(&self, collection: Arc<String>, secret: Arc<String>) -> Result {
        self.pass
            .delete_password(Self::collection_path(&collection).join(&*secret))
            .await?;
        self.pass
            .delete_password(Self::meta_path(&collection, &secret))
            .await?;
        self.cache
            .write()
            .await
            .remove(&(collection.to_string(), secret.to_string()));
        Ok(())
    }

    async fn stat_secret(&self, collection_id: &str, secret_id: &str) -> Result<Metadata> {
        let path = Self::collection_path(collection_id).join(secret_id);
        Ok(fs::metadata(self.gpg_file(&path)).await?)
    }

    async fn create_secret(
        &self,
        collection_id: Arc<String>,
        label: Option<String>,
        secret: Vec<u8>,
        attributes: Arc<HashMap<String, String>>,
    ) -> Result<String> {
        self.collection_exists(&collection_id).await?;

        // opaque id: the filename must not leak the label
        let secret_id = nanoid!(16, &NANOID_ALPHABET);
        self.pass
            .write_password(
                Self::collection_path(&collection_id).join(&secret_id),
                secret,
            )
            .await?;
        let meta = Meta {
            label: label.unwrap_or_else(|| "Untitled Secret".into()),
            attributes: (*attributes).clone(),
        };
        self.write_meta(&collection_id, &secret_id, meta).await?;
        Ok(secret_id)
    }

    async fn set_secret(&self, collection_id: &str, secret_id: &str, value: Vec<u8>) -> Result {
        self.pass
            .write_password(Self::collection_path(collection_id).join(secret_id), value)
            .await
    }

    async fn set_secret_label(
        &self,
        collection: Arc<String>,
        secret: Arc<String>,
        label: String,
    ) -> Result {
        self.update_meta(&collection, &secret, |m| m.label = label)
            .await
    }

    async fn get_secret_label(
        &self,
        collection: Arc<String>,
        secret: Arc<String>,
    ) -> Result<String> {
        Ok(self.meta(&collection, &secret, false).await?.label)
    }

    async fn set_secret_attrs(
        &self,
        collection_id: Arc<String>,
        secret_id: Arc<String>,
        attrs: HashMap<String, String>,
    ) -> Result {
        self.update_meta(&collection_id, &secret_id, |m| m.attributes = attrs)
            .await
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use tempfile::{tempdir, TempDir};
    use tokio::process::Command;

    use super::*;

    const RECIPIENT: &str = "pass-secret-service-test@example.invalid";

    struct Fixture {
        dir: TempDir,
        pass: PasswordStore,
    }

    impl Fixture {
        async fn new() -> Self {
            let dir = tempdir().unwrap();
            let gpg_home = dir.path().join("gnupg");
            fs::create_dir(&gpg_home).await.unwrap();
            fs::set_permissions(&gpg_home, std::fs::Permissions::from_mode(0o700))
                .await
                .unwrap();
            let output = Command::new("gpg")
                .arg("--batch")
                .arg("--homedir")
                .arg(&gpg_home)
                .args(["--passphrase", "", "--quick-generate-key", RECIPIENT])
                .args(["rsa2048", "encr", "0"])
                .output()
                .await
                .unwrap();
            assert!(
                output.status.success(),
                "failed to create test GPG key: {}",
                String::from_utf8_lossy(&output.stderr)
            );

            let store_dir = dir.path().join("password-store");
            fs::create_dir(&store_dir).await.unwrap();
            fs::write(store_dir.join(".gpg-id"), RECIPIENT)
                .await
                .unwrap();
            let pass = PasswordStore::for_test(store_dir, &gpg_home);
            Self { dir, pass }
        }

        fn collection_dir(&self, id: &str) -> PathBuf {
            self.pass.directory.join(PASS_SUBDIR).join(id)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::process::Command::new("gpgconf")
                .arg("--homedir")
                .arg(self.dir.path().join("gnupg"))
                .args(["--kill", "gpg-agent"])
                .status();
        }
    }

    fn attrs(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    async fn collection(store: &GpgSecretStore<'_>) -> Arc<String> {
        Arc::new(
            store
                .create_collection(Some("test".into()), None)
                .await
                .unwrap(),
        )
    }

    async fn secret(
        store: &GpgSecretStore<'_>,
        collection: &Arc<String>,
        label: &str,
        attributes: HashMap<String, String>,
    ) -> Arc<String> {
        Arc::new(
            store
                .create_secret(
                    collection.clone(),
                    Some(label.into()),
                    b"secret value".to_vec(),
                    Arc::new(attributes),
                )
                .await
                .unwrap(),
        )
    }

    #[tokio::test]
    async fn delete_secret_removes_all_secret_storage() {
        let fx = Fixture::new().await;
        let store = GpgSecretStore::new(&fx.pass).await.unwrap();
        let c = collection(&store).await;
        let attributes = attrs(&[("application", "regression-test"), ("account", "example")]);
        let s = secret(&store, &c, "Secret label", attributes.clone()).await;
        let dir = fx.collection_dir(&c);

        assert_eq!(
            store.get_secret_label(c.clone(), s.clone()).await.unwrap(),
            "Secret label"
        );
        assert_eq!(
            store.read_secret_attrs(c.clone(), s.clone()).await.unwrap(),
            attributes
        );
        assert_eq!(
            store.read_secret(&c, &s, false).await.unwrap(),
            b"secret value"
        );
        assert_eq!(store.list_secrets(&c).await.unwrap(), vec![s.to_string()]);

        store.delete_secret(c.clone(), s.clone()).await.unwrap();

        assert!(!dir.join(format!("{s}.gpg")).exists());
        assert!(!dir.join(META_DIR).join(format!("{s}.gpg")).exists());
        assert!(store.cache.read().await.is_empty());
        assert!(store
            .search_collection(c.clone(), Arc::new(attributes))
            .await
            .unwrap()
            .is_empty());
        assert!(store.read_secret_attrs(c, s).await.is_err());
    }

    #[tokio::test]
    async fn metadata_is_encrypted_on_disk() {
        let fx = Fixture::new().await;
        let store = GpgSecretStore::new(&fx.pass).await.unwrap();
        let c = collection(&store).await;
        let s = secret(
            &store,
            &c,
            "Quite Distinctive Label",
            attrs(&[("unique-key-xyz", "unique-value-xyz")]),
        )
        .await;

        let raw = fs::read(
            fx.collection_dir(&c)
                .join(META_DIR)
                .join(format!("{s}.gpg")),
        )
        .await
        .unwrap();
        for needle in ["Quite Distinctive", "unique-key-xyz", "unique-value-xyz"] {
            assert!(!raw.windows(needle.len()).any(|w| w == needle.as_bytes()));
        }
    }

    #[tokio::test]
    async fn secret_ids_are_opaque() {
        let fx = Fixture::new().await;
        let store = GpgSecretStore::new(&fx.pass).await.unwrap();
        let c = collection(&store).await;
        let s = secret(&store, &c, "Hunter Two Bank", HashMap::new()).await;

        assert_eq!(s.len(), 16);
        let id = s.to_lowercase();
        assert!(!id.contains("hunter") && !id.contains("bank"));
    }

    #[tokio::test]
    async fn search_matches_attribute_subsets() {
        let fx = Fixture::new().await;
        let store = GpgSecretStore::new(&fx.pass).await.unwrap();
        let c = collection(&store).await;
        let a = secret(&store, &c, "a", attrs(&[("app", "x"), ("user", "alice")])).await;
        let b = secret(&store, &c, "b", attrs(&[("app", "x"), ("user", "bob")])).await;

        let search = |pairs: &[(&str, &str)]| {
            let query = Arc::new(attrs(pairs));
            let (store, c) = (&store, c.clone());
            async move {
                let mut found = store.search_collection(c, query).await.unwrap();
                found.sort();
                found
            }
        };
        let mut both = vec![a.to_string(), b.to_string()];
        both.sort();

        assert_eq!(search(&[("app", "x")]).await, both);
        assert_eq!(
            search(&[("app", "x"), ("user", "bob")]).await,
            vec![b.to_string()]
        );
        assert!(search(&[("app", "y")]).await.is_empty());
        assert!(search(&[]).await.is_empty());

        let all = store
            .search_all_collections(attrs(&[("user", "alice")]))
            .await
            .unwrap();
        assert_eq!(all[c.as_str()], vec![a.to_string()]);

        store
            .set_secret_attrs(c.clone(), a.clone(), attrs(&[("app", "z")]))
            .await
            .unwrap();
        assert_eq!(search(&[("app", "z")]).await, vec![a.to_string()]);
        assert_eq!(search(&[("user", "alice")]).await, Vec::<String>::new());
    }

    #[tokio::test]
    async fn search_skips_undecryptable_items() {
        let fx = Fixture::new().await;
        let store = GpgSecretStore::new(&fx.pass).await.unwrap();
        let c = collection(&store).await;
        let good = secret(&store, &c, "good", attrs(&[("k", "v")])).await;
        let bad = secret(&store, &c, "bad", attrs(&[("k", "v")])).await;
        fs::write(
            fx.collection_dir(&c)
                .join(META_DIR)
                .join(format!("{bad}.gpg")),
            b"not gpg",
        )
        .await
        .unwrap();

        let found = store
            .search_collection(c, Arc::new(attrs(&[("k", "v")])))
            .await
            .unwrap();
        assert_eq!(found, vec![good.to_string()]);
    }

    #[tokio::test]
    async fn aliases_roundtrip_and_collection_delete_clears_them() {
        let fx = Fixture::new().await;
        let store = GpgSecretStore::new(&fx.pass).await.unwrap();
        let c = collection(&store).await;
        let alias = Arc::new("work".to_string());

        assert!(store.get_alias(alias.clone()).await.is_err());
        store
            .set_alias(alias.clone(), Some(c.to_string()))
            .await
            .unwrap();
        store
            .set_alias(Arc::new("other".into()), Some(c.to_string()))
            .await
            .unwrap();
        assert_eq!(store.get_alias(alias.clone()).await.unwrap(), *c);

        let mut for_c = store.list_aliases_for_collection(c.clone()).await.unwrap();
        for_c.sort();
        assert_eq!(for_c, ["other", "work"]);
        assert_eq!(store.list_all_aliases().await.unwrap().len(), 1);

        store.set_alias(alias.clone(), None).await.unwrap();
        store.set_alias(alias.clone(), None).await.unwrap();
        assert!(store.get_alias(alias.clone()).await.is_err());

        store.delete_collection(c.clone()).await.unwrap();
        assert!(store.list_all_aliases().await.unwrap().is_empty());
        assert!(!fx.collection_dir(&c).exists());
        assert!(!store.collections().await.contains(&*c));
    }

    #[tokio::test]
    async fn create_collection_reuses_aliased_collection() {
        let fx = Fixture::new().await;
        let store = GpgSecretStore::new(&fx.pass).await.unwrap();
        let first = store
            .create_collection(Some("Default".into()), Some("default".into()))
            .await
            .unwrap();
        let again = store
            .create_collection(Some("Renamed".into()), Some("default".into()))
            .await
            .unwrap();
        let kept = store
            .create_collection(None, Some("default".into()))
            .await
            .unwrap();
        let other = store
            .create_collection(Some("Default".into()), None)
            .await
            .unwrap();

        assert_eq!(first, again);
        assert_eq!(first, kept);
        assert_ne!(first, other);
        assert_eq!(store.get_label(Arc::new(first)).await.unwrap(), "Renamed");
        assert_eq!(store.get_label(Arc::new(other)).await.unwrap(), "Default");
    }

    #[tokio::test]
    async fn cache_revalidates_against_file_mtime() {
        let fx = Fixture::new().await;
        let store = GpgSecretStore::new(&fx.pass).await.unwrap();
        let c = collection(&store).await;
        let s = secret(&store, &c, "before", attrs(&[("k", "v")])).await;
        assert_eq!(
            store.get_secret_label(c.clone(), s.clone()).await.unwrap(),
            "before"
        );

        let path = GpgSecretStore::meta_path(&c, &s);
        let json = br#"{"label":"after","attributes":{"k":"changed"}}"#.to_vec();
        fx.pass.write_password(&path, json).await.unwrap();
        let file = std::fs::File::options()
            .write(true)
            .open(store.gpg_file(&path))
            .unwrap();
        file.set_modified(SystemTime::now() + std::time::Duration::from_secs(60))
            .unwrap();

        assert_eq!(
            store.get_secret_label(c.clone(), s.clone()).await.unwrap(),
            "after"
        );
        assert_eq!(
            store.read_secret_attrs(c, s).await.unwrap(),
            attrs(&[("k", "changed")])
        );
    }
}
