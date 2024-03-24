use notify_debouncer_full::notify::event::{AccessKind, AccessMode};
use notify_debouncer_full::notify::{RecursiveMode, Watcher};
use notify_debouncer_full::notify::{EventKind};
use std::fs::OpenOptions;
use std::{path::Path, time::Duration};
use suppaftp::native_tls::TlsConnector;
use suppaftp::{NativeTlsConnector, NativeTlsFtpStream};

use notify_debouncer_full::{new_debouncer, DebounceEventResult, DebouncedEvent};
use tokio;

#[tokio::main]
async fn main() -> Result<(), notify_debouncer_full::notify::Error> {
    dotenv::dotenv().unwrap();

    let ftp_stream =
        NativeTlsFtpStream::connect(std::env::var("REMOTE_HOST").expect("Missing remote HOST"))
            .unwrap_or_else(|err| {
                panic!("{err}");
            });
    let ctx = NativeTlsConnector::from(TlsConnector::new().unwrap());
    let mut ftp_stream = ftp_stream
        .into_secure(
            ctx,
            &std::env::var("REMOTE_DOMAIN").expect("Missing remote DOMAIN"),
        )
        .unwrap();
    ftp_stream
        .login(
            &std::env::var("REMOTE_USER").expect("Missing remote USER"),
            &std::env::var("REMOTE_PASSWORD").expect("Missing remote PASSWORD"),
        )
        .unwrap();

    println!("{:?}", ftp_stream.nlst(None));

    let local_folder = std::env::var("LOCAL_FOLDER").expect("Missing local FOLDER");
    let local_folder_copy = local_folder.clone();

    // Automatically select the best implementation for your platform.
    let mut debouncer = new_debouncer(
        Duration::from_secs(5),
        None,
        move |res: DebounceEventResult| match res {
            Ok(events) => {
                for DebouncedEvent { event, .. } in events {
                    println!("event: {:?}", event);
                    match event.kind {
                        EventKind::Access(AccessKind::Close(AccessMode::Write)) => {
                            println!("{:?}", ftp_stream.list(None));
                            println!("paths");
                            for path in event.paths {
                                let mut file =
                                    OpenOptions::new().read(true).open(path.clone()).unwrap();
                                let remote_filename =
                                    path.to_str().unwrap().replace(&local_folder_copy, "");
                                println!("trying upload... {remote_filename}");
                                let parts = remote_filename
                                    .split("/")
                                    .filter(|t| *t != "")
                                    .collect::<Vec<_>>();
                                if parts.iter().any(|k| k.starts_with('.')) {
                                    println!("Skipping hidden files");
                                    continue;
                                }
                                ftp_stream
                                    .cwd(
                                        &std::env::var("REMOTE_FOLDER")
                                            .expect("Missing remote FOLDER"),
                                    )
                                    .unwrap();
                                for part in &parts[0..parts.len() - 1] {
                                    println!("{part:?}");
                                    if !ftp_stream.nlst(None).unwrap().contains(&part.to_string()) {
                                        println!("Making directory");
                                        ftp_stream.mkdir(part).unwrap();
                                    }
                                    ftp_stream.cwd(&part.to_string()).unwrap();
                                }
                                let bytes_written =
                                    ftp_stream.put_file(parts[parts.len() - 1], &mut file);
                                println!("wrote {bytes_written:?} bytes");
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

    let path = std::fs::canonicalize(&Path::new(&shellexpand::tilde(&local_folder).to_string()))?;
    println!("{path:?}");

    // Add a path to be watched. All files and directories at that path and
    // below will be monitored for changes.
    watcher.watch(&path, RecursiveMode::Recursive)?;

    std::thread::sleep(Duration::from_secs(u64::MAX));
    Ok(())
}
