use notify_debouncer_full::notify::event::{AccessKind, AccessMode};
use notify_debouncer_full::notify::{EventKind, INotifyWatcher, RecommendedWatcher};
use notify_debouncer_full::notify::{Error, RecursiveMode, Watcher};
use std::fs::OpenOptions;
use std::sync::mpsc::Receiver;
use std::{path::Path, time::Duration};
use suppaftp::native_tls::TlsConnector;
use suppaftp::{NativeTlsConnector, NativeTlsFtpStream};

use notify_debouncer_full::{new_debouncer, DebounceEventResult, DebouncedEvent, Debouncer, FileIdMap};
use tokio;

struct ModificationEvent {
    local_filename: String,
    remote_filename: String,
}

#[derive(Clone)]
struct Config {
    remote_domain: String,
    remote_origin: String,
    remote_user: String,
    remote_password: String,
    remote_folder: String,
    local_folder: String,
}

#[derive(Debug)]
enum ConfigLoadError {
    DotEnvError(dotenv::Error),
    EnvError(std::env::VarError),
}

impl From<dotenv::Error> for ConfigLoadError {
    fn from(value: dotenv::Error) -> Self {
        ConfigLoadError::DotEnvError(value)
    }
}

impl From<std::env::VarError> for ConfigLoadError {
    fn from(value: std::env::VarError) -> Self {
        ConfigLoadError::EnvError(value)
    }
}

impl Config {
    fn from_env() -> Result<Config, ConfigLoadError> {
        dotenv::dotenv()?;

        return Ok(Config {
            remote_domain: std::env::var("REMOTE_DOMAIN")?,
            remote_origin: std::env::var("REMOTE_HOST")?,
            remote_user: std::env::var("REMOTE_USER")?,
            remote_password: std::env::var("REMOTE_PASSWORD")?,
            remote_folder: std::env::var("REMOTE_FOLDER")?,
            local_folder: shellexpand::tilde(&std::env::var("LOCAL_FOLDER")?).to_string(),
        });
    }
}

fn watch_folder(
    config: Config,
    stream: tokio::sync::mpsc::Sender<ModificationEvent>,
) -> Result<Debouncer<RecommendedWatcher, FileIdMap>, Error> {
    let local_folder = config.local_folder.clone();

    let mut debouncer = new_debouncer(
        Duration::from_secs(5),
        None,
        move |res: DebounceEventResult| match res {
            Ok(events) => {
                for DebouncedEvent { event, .. } in events {
                    println!("event: {:?}", event);
                    match event.kind {
                        EventKind::Access(AccessKind::Close(AccessMode::Write)) => {
                            for path in event.paths {
                                let local_filename = path.to_str().unwrap().to_string();
                                let remote_filename =
                                    path.to_str().unwrap().replace(&local_folder, "");
                                println!("trying upload... {remote_filename}");

                                stream.blocking_send(ModificationEvent {
                                    local_filename,
                                    remote_filename,
                                }).unwrap();
                            }
                        }
                        _ => (),
                    }
                }
            }
            Err(e) => println!("watch error: {:?}", e),
        },
    )?;
    let watcher = debouncer.watcher();

    let local_folder = config.local_folder.clone();
    println!("{local_folder:?}");

    // Add a path to be watched. All files and directories at that path and
    // below will be monitored for changes.
    watcher.watch(&Path::new(&local_folder), RecursiveMode::Recursive)?;

    Ok(debouncer)
}

#[tokio::main]
async fn main() -> Result<(), notify_debouncer_full::notify::Error> {
    let config = Config::from_env().unwrap();

    let ftp_stream = NativeTlsFtpStream::connect(&config.remote_origin).unwrap_or_else(|err| {
        panic!("{err}");
    });
    let ctx = NativeTlsConnector::from(TlsConnector::new().unwrap());
    let mut ftp_stream = ftp_stream
        .into_secure(
            ctx,
            &config.remote_domain,
        )
        .unwrap();
    ftp_stream
        .login(
            &config.remote_user,
            &config.remote_password,
        )
        .unwrap();

    println!("NLST output: {:?}", ftp_stream.nlst(None));

    let (sender, mut receiver) = tokio::sync::mpsc::channel(24);
    let _watcher = watch_folder(config.clone(), sender)?;

    while let Some(ModificationEvent {
        local_filename,
        remote_filename,
    }) = receiver.recv().await
    {
        ftp_stream.cwd(&config.remote_folder).unwrap();

        let parts = remote_filename
            .split("/")
            .filter(|t| *t != "")
            .collect::<Vec<_>>();
        if parts.iter().any(|k| k.starts_with('.')) {
            println!("Skipping hidden files");
            continue;
        }
        for part in &parts[0..parts.len() - 1] {
            println!("{part:?}");
            if !ftp_stream.nlst(None).unwrap().contains(&part.to_string()) {
                println!("Making directory");
                ftp_stream.mkdir(part).unwrap();
            }
            ftp_stream.cwd(&part.to_string()).unwrap();
        }
        let mut file = OpenOptions::new()
            .read(true)
            .open(local_filename.clone())
            .unwrap();
        let bytes_written = ftp_stream.put_file(parts[parts.len() - 1], &mut file);
        println!("wrote {bytes_written:?} bytes");
    }
    Ok(())
}
