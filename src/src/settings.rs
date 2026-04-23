use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

const HOSTVEIL_CONFIG_DIR_ENV: &str = "HOSTVEIL_CONFIG_DIR";
const XDG_CONFIG_HOME_ENV: &str = "XDG_CONFIG_HOME";
const HOME_ENV: &str = "HOME";
const CONFIG_FILE_NAME: &str = "config.json";

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct AppSettings {
    pub locale: Option<String>,
    pub theme: Option<String>,
}

pub fn load() -> AppSettings {
    config_file_path()
        .ok()
        .and_then(|path| load_from_path(&path).ok())
        .unwrap_or_default()
}

pub fn persist_locale(locale: &str) -> io::Result<()> {
    let mut settings = load();
    settings.locale = Some(locale.to_owned());
    save(&settings)
}

pub fn persist_theme(theme: &str) -> io::Result<()> {
    let mut settings = load();
    settings.theme = Some(theme.to_owned());
    save(&settings)
}

fn save(settings: &AppSettings) -> io::Result<()> {
    let path = config_file_path()?;
    save_to_path(&path, settings)
}

fn load_from_path(path: &Path) -> io::Result<AppSettings> {
    let text = fs::read_to_string(path)?;
    serde_json::from_str(&text).map_err(|error| io::Error::other(error.to_string()))
}

fn save_to_path(path: &Path, settings: &AppSettings) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let text = serde_json::to_string_pretty(settings)
        .map_err(|error| io::Error::other(error.to_string()))?;
    fs::write(path, text + "\n")
}

fn config_file_path() -> io::Result<PathBuf> {
    resolve_config_dir(
        env::var(HOSTVEIL_CONFIG_DIR_ENV).ok().as_deref(),
        env::var(XDG_CONFIG_HOME_ENV).ok().as_deref(),
        env::var(HOME_ENV).ok().as_deref(),
    )
    .map(|dir| dir.join(CONFIG_FILE_NAME))
    .ok_or_else(|| io::Error::other("failed to resolve a hostveil config directory"))
}

fn resolve_config_dir(
    explicit_dir: Option<&str>,
    xdg_config_home: Option<&str>,
    home: Option<&str>,
) -> Option<PathBuf> {
    explicit_dir
        .filter(|value| !value.trim().is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            xdg_config_home
                .filter(|value| !value.trim().is_empty())
                .map(PathBuf::from)
                .map(|path| path.join("hostveil"))
        })
        .or_else(|| {
            home.filter(|value| !value.trim().is_empty())
                .map(PathBuf::from)
                .map(|path| path.join(".config").join("hostveil"))
        })
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{AppSettings, load_from_path, resolve_config_dir, save_to_path};

    fn temp_settings_path(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should move forward")
            .as_nanos();
        std::env::temp_dir()
            .join(format!(
                "hostveil-settings-{name}-{}-{nanos}",
                std::process::id()
            ))
            .join("config.json")
    }

    #[test]
    fn prefers_explicit_config_dir() {
        let dir = resolve_config_dir(Some("/tmp/hostveil"), Some("/xdg"), Some("/home/user"))
            .expect("dir should resolve");

        assert_eq!(dir, PathBuf::from("/tmp/hostveil"));
    }

    #[test]
    fn falls_back_to_xdg_config_home() {
        let dir =
            resolve_config_dir(None, Some("/xdg"), Some("/home/user")).expect("dir should resolve");

        assert_eq!(dir, PathBuf::from("/xdg/hostveil"));
    }

    #[test]
    fn falls_back_to_home_config_dir() {
        let dir = resolve_config_dir(None, None, Some("/home/user")).expect("dir should resolve");

        assert_eq!(dir, PathBuf::from("/home/user/.config/hostveil"));
    }

    #[test]
    fn returns_none_when_no_config_base_exists() {
        assert!(resolve_config_dir(None, None, None).is_none());
    }

    #[test]
    fn saves_settings_as_json() {
        let path = temp_settings_path("save");
        let settings = AppSettings {
            locale: Some(String::from("ko")),
            theme: Some(String::from("nord")),
        };

        save_to_path(&path, &settings).expect("settings should save");

        let written = fs::read_to_string(&path).expect("settings file should exist");
        assert!(written.contains("\"locale\": \"ko\""));
        assert!(written.contains("\"theme\": \"nord\""));

        fs::remove_dir_all(path.parent().expect("config dir should exist"))
            .expect("temp dir should be removed");
    }

    #[test]
    fn loads_saved_theme_and_locale_round_trip() {
        let path = temp_settings_path("roundtrip");
        let settings = AppSettings {
            locale: Some(String::from("en")),
            theme: Some(String::from("tokyo_night")),
        };

        save_to_path(&path, &settings).expect("settings should save");

        let loaded = load_from_path(&path).expect("settings should load");
        assert_eq!(loaded, settings);

        fs::remove_dir_all(path.parent().expect("config dir should exist"))
            .expect("temp dir should be removed");
    }
}
