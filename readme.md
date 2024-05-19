# Inoty FTP Sync

This project can watch a folder and upload changed files using FTP.

## Configuring

This project can be configured using environment variables, or a `.env` file:

```bash
REMOTE_HOST=
REMOTE_DOMAIN= # Remote host without port number
REMOTE_USER=
REMOTE_PASSWORD=
REMOTE_FOLDER="/upload/obsidian"
LOCAL_FOLDER="~/Obsidian"

RUST_LOG=debug # Enable logging
```

## Limitations

* The entire file will always be uploaded. This may be inefficient for large files where only a little bit has changed.
* Only uploading, no downloading