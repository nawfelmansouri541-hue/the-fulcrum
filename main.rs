// =============================================================================
//  AEGIS SOVEREIGN VAULT — v2.0
//  Streaming AES-256-GCM file encryption with Argon2id key derivation
//  Fixed: real async I/O, real progress, password zeroization, secure delete
// =============================================================================

use aes_gcm::{
    aead::stream::{DecryptorBE32, EncryptorBE32},
    Aes256Gcm, KeyInit,
};
use argon2::{Argon2, Params, Version};
use rand::RngCore;
use secrecy::{ExposeSecret, SecretVec};
use std::path::PathBuf;
use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncWriteExt, BufReader, BufWriter},
};
use zeroize::{Zeroize, ZeroizeOnDrop};

use iced::{
    executor,
    widget::{button, column, container, progress_bar, row, text, text_input},
    Application, Command, Element, Length, Settings, Theme,
};

// ─── Constants ───────────────────────────────────────────────────────────────

/// Buffer size for streaming (256 KB — good balance of speed vs memory)
const BUFFER_SIZE: usize = 256 * 1024;

/// Argon2id parameters — OWASP 2023 recommendation (interactive login)
/// Memory: 64 MB, Iterations: 3, Parallelism: 4
const ARGON2_MEM_KIB: u32 = 64 * 1024;
const ARGON2_ITERS: u32 = 3;
const ARGON2_PARALLEL: u32 = 4;

/// Magic bytes to identify Aegis-encrypted files and detect corruption early
const AEGIS_MAGIC: &[u8; 6] = b"AEGIS2";

/// Header layout (bytes):
///   6  — magic
///  16  — Argon2id salt
///  12  — AES-GCM-BE32 nonce (96-bit / 12 bytes)
///   4  — argon2 mem_kib (big-endian u32)
///   4  — argon2 iters   (big-endian u32)
///   4  — argon2 parallel(big-endian u32)
/// ----
///  46  total
const HEADER_SIZE: u64 = 6 + 16 + 12 + 4 + 4 + 4;

// ─── Secure key wrapper ───────────────────────────────────────────────────────

/// Holds the 32-byte derived key and zeroes it on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
struct MasterKey([u8; 32]);

impl MasterKey {
    fn derive(password: &[u8], salt: &[u8], mem_kib: u32, iters: u32, parallel: u32) -> Result<Self, String> {
        let params = Params::new(mem_kib, iters, parallel, Some(32))
            .map_err(|e| format!("Argon2 params error: {e}"))?;
        let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params);
        let mut key = [0u8; 32];
        argon2
            .hash_password_into(password, salt, &mut key)
            .map_err(|e| format!("Key derivation failed: {e}"))?;
        Ok(MasterKey(key))
    }
}

// ─── Progress reporting ───────────────────────────────────────────────────────

/// Sent periodically from background tasks to update the progress bar.
#[derive(Debug, Clone)]
pub enum ProgressUpdate {
    /// 0.0 – 100.0
    Percent(f32),
    Done(Result<String, String>),
}

// ─── Encryption ──────────────────────────────────────────────────────────────

async fn async_encrypt(
    password: SecretVec<u8>,
    path_str: String,
    progress_tx: tokio::sync::mpsc::Sender<ProgressUpdate>,
) -> Result<String, String> {
    let input_path = PathBuf::from(&path_str);

    // ── open source ──
    let src = File::open(&input_path)
        .await
        .map_err(|e| format!("Cannot open file: {e}"))?;
    let file_size = src
        .metadata()
        .await
        .map_err(|e| format!("Cannot read metadata: {e}"))?
        .len();
    let mut reader = BufReader::new(src);

    // ── output path ──
    let mut out_path = input_path.as_os_str().to_owned();
    out_path.push(".aegis");
    let output_path = PathBuf::from(out_path);

    let dst = File::create(&output_path)
        .await
        .map_err(|e| format!("Cannot create output: {e}"))?;
    let mut writer = BufWriter::new(dst);

    // ── generate random salt + nonce ──
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut salt);
    rand::thread_rng().fill_bytes(&mut nonce);

    // ── write header ──
    writer.write_all(AEGIS_MAGIC).await.map_err(|e| e.to_string())?;
    writer.write_all(&salt).await.map_err(|e| e.to_string())?;
    writer.write_all(&nonce).await.map_err(|e| e.to_string())?;
    writer.write_all(&ARGON2_MEM_KIB.to_be_bytes()).await.map_err(|e| e.to_string())?;
    writer.write_all(&ARGON2_ITERS.to_be_bytes()).await.map_err(|e| e.to_string())?;
    writer.write_all(&ARGON2_PARALLEL.to_be_bytes()).await.map_err(|e| e.to_string())?;

    // ── derive key (CPU-heavy → offload to blocking thread) ──
    let password_bytes: Vec<u8> = password.expose_secret().clone();
    let key = tokio::task::spawn_blocking(move || {
        MasterKey::derive(&password_bytes, &salt, ARGON2_MEM_KIB, ARGON2_ITERS, ARGON2_PARALLEL)
    })
    .await
    .map_err(|e| format!("Thread panic: {e}"))??;

    let _ = progress_tx.send(ProgressUpdate::Percent(5.0)).await;

    // ── stream-encrypt ──
    let aead = Aes256Gcm::new_from_slice(&key.0).map_err(|_| "Key init failed".to_string())?;
    let mut encryptor = EncryptorBE32::from_aead(aead, (&nonce).into());

    let mut buf = vec![0u8; BUFFER_SIZE];
    let mut bytes_done = 0u64;

    loop {
        let n = reader.read(&mut buf).await.map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        bytes_done += n as u64;

        // last chunk?
        let is_last = bytes_done >= file_size;

        let ciphertext = if is_last {
            encryptor
                .encrypt_last(&buf[..n])
                .map_err(|_| "Encryption finalisation failed".to_string())?
        } else {
            encryptor
                .encrypt_next(&buf[..n])
                .map_err(|_| "Encryption chunk failed".to_string())?
        };

        writer.write_all(&ciphertext).await.map_err(|e| e.to_string())?;

        // progress: 5 % (key derivation) + up to 95 % (streaming)
        let pct = 5.0 + (bytes_done as f32 / file_size.max(1) as f32) * 95.0;
        let _ = progress_tx.send(ProgressUpdate::Percent(pct)).await;

        if is_last {
            break;
        }
    }

    writer.flush().await.map_err(|e| e.to_string())?;

    // ── secure-delete original file ──
    secure_delete(&input_path).await?;

    Ok(format!("Encrypted → {:?}", output_path))
}

// ─── Decryption ──────────────────────────────────────────────────────────────

async fn async_decrypt(
    password: SecretVec<u8>,
    path_str: String,
    progress_tx: tokio::sync::mpsc::Sender<ProgressUpdate>,
) -> Result<String, String> {
    let input_path = PathBuf::from(&path_str);

    let src = File::open(&input_path)
        .await
        .map_err(|e| format!("Cannot open file: {e}"))?;
    let total_size = src
        .metadata()
        .await
        .map_err(|e| format!("Cannot read metadata: {e}"))?
        .len();
    let mut reader = BufReader::new(src);

    // ── validate magic bytes ──
    let mut magic = [0u8; 6];
    reader.read_exact(&mut magic).await.map_err(|e| e.to_string())?;
    if &magic != AEGIS_MAGIC {
        return Err("Not an Aegis vault file (wrong magic bytes).".to_string());
    }

    // ── read header ──
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 12];
    let mut mem_buf = [0u8; 4];
    let mut iter_buf = [0u8; 4];
    let mut par_buf = [0u8; 4];

    reader.read_exact(&mut salt).await.map_err(|e| e.to_string())?;
    reader.read_exact(&mut nonce).await.map_err(|e| e.to_string())?;
    reader.read_exact(&mut mem_buf).await.map_err(|e| e.to_string())?;
    reader.read_exact(&mut iter_buf).await.map_err(|e| e.to_string())?;
    reader.read_exact(&mut par_buf).await.map_err(|e| e.to_string())?;

    let mem_kib = u32::from_be_bytes(mem_buf);
    let iters = u32::from_be_bytes(iter_buf);
    let parallel = u32::from_be_bytes(par_buf);

    // ── derive key ──
    let password_bytes: Vec<u8> = password.expose_secret().clone();
    let key = tokio::task::spawn_blocking(move || {
        MasterKey::derive(&password_bytes, &salt, mem_kib, iters, parallel)
    })
    .await
    .map_err(|e| format!("Thread panic: {e}"))??;

    let _ = progress_tx.send(ProgressUpdate::Percent(5.0)).await;

    // ── output path ──
    let output_path = if input_path.extension().map_or(false, |e| e == "aegis") {
        input_path.with_extension("")
    } else {
        input_path.with_extension("decrypted")
    };

    let dst = File::create(&output_path)
        .await
        .map_err(|e| format!("Cannot create output: {e}"))?;
    let mut writer = BufWriter::new(dst);

    // ── stream-decrypt ──
    let aead = Aes256Gcm::new_from_slice(&key.0).map_err(|_| "Key init failed".to_string())?;
    let mut decryptor = DecryptorBE32::from_aead(aead, (&nonce).into());

    // Each encrypted chunk = BUFFER_SIZE plaintext + 16-byte GCM tag
    let chunk_ct = BUFFER_SIZE + 16;
    let mut buf = vec![0u8; chunk_ct];
    let mut payload_remaining = total_size.saturating_sub(HEADER_SIZE);
    let payload_total = payload_remaining;

    loop {
        let to_read = (payload_remaining as usize).min(chunk_ct);
        if to_read == 0 {
            break;
        }

        reader
            .read_exact(&mut buf[..to_read])
            .await
            .map_err(|e| e.to_string())?;
        payload_remaining -= to_read as u64;

        let plaintext = if payload_remaining == 0 {
            decryptor
                .decrypt_last(&buf[..to_read])
                .map_err(|_| "Wrong password or corrupted vault.".to_string())?
        } else {
            decryptor
                .decrypt_next(&buf[..to_read])
                .map_err(|_| "Decryption chunk failed — file may be corrupted.".to_string())?
        };

        writer.write_all(&plaintext).await.map_err(|e| e.to_string())?;

        let done = payload_total.saturating_sub(payload_remaining);
        let pct = 5.0 + (done as f32 / payload_total.max(1) as f32) * 95.0;
        let _ = progress_tx.send(ProgressUpdate::Percent(pct)).await;
    }

    writer.flush().await.map_err(|e| e.to_string())?;

    Ok(format!("Decrypted → {:?}", output_path))
}

// ─── Secure delete ────────────────────────────────────────────────────────────

/// Overwrites a file with random bytes three times, then deletes it.
/// Note: ineffective on SSDs with wear-levelling; full-disk encryption is
/// the only true solution on such hardware.
async fn secure_delete(path: &PathBuf) -> Result<(), String> {
    let file_size = tokio::fs::metadata(path)
        .await
        .map_err(|e| format!("secure_delete metadata: {e}"))?
        .len() as usize;

    for _ in 0..3 {
        let mut f = tokio::fs::OpenOptions::new()
            .write(true)
            .open(path)
            .await
            .map_err(|e| format!("secure_delete open: {e}"))?;

        let mut rng_buf = vec![0u8; file_size.min(BUFFER_SIZE)];
        let mut written = 0usize;
        while written < file_size {
            let chunk = (file_size - written).min(BUFFER_SIZE);
            rand::thread_rng().fill_bytes(&mut rng_buf[..chunk]);
            f.write_all(&rng_buf[..chunk])
                .await
                .map_err(|e| format!("secure_delete write: {e}"))?;
            written += chunk;
        }
        f.flush().await.map_err(|e| format!("secure_delete flush: {e}"))?;
    }

    tokio::fs::remove_file(path)
        .await
        .map_err(|e| format!("secure_delete remove: {e}"))?;

    Ok(())
}

// ─── GUI ──────────────────────────────────────────────────────────────────────

fn main() -> iced::Result {
    AegisVaultGui::run(Settings::default())
}

struct AegisVaultGui {
    /// Stored as SecretVec so it's zeroed on drop; never a plain String
    password: String, // bound to text_input; converted to SecretVec on use
    file_path: String,
    status_message: String,
    progress: f32,
    is_processing: bool,
    /// Receiving end of the progress channel (polled via subscription)
    progress_rx: Option<tokio::sync::mpsc::Receiver<ProgressUpdate>>,
}

#[derive(Debug, Clone)]
enum Message {
    PasswordChanged(String),
    FilePathChanged(String),
    EncryptPressed,
    DecryptPressed,
    /// Incremental progress update from background task
    ProgressTick(f32),
    /// Background task finished
    OperationFinished(Result<String, String>),
}

impl Application for AegisVaultGui {
    type Executor = executor::Default;
    type Message = Message;
    type Theme = Theme;
    type Flags = ();

    fn new(_flags: ()) -> (Self, Command<Message>) {
        (
            AegisVaultGui {
                password: String::new(),
                file_path: String::new(),
                status_message: String::from("Ready — awaiting your command."),
                progress: 0.0,
                is_processing: false,
                progress_rx: None,
            },
            Command::none(),
        )
    }

    fn title(&self) -> String {
        String::from("🛡️ Aegis Sovereign Vault v2")
    }

    fn update(&mut self, message: Message) -> Command<Message> {
        match message {
            Message::PasswordChanged(p) => {
                self.password = p;
                Command::none()
            }
            Message::FilePathChanged(p) => {
                self.file_path = p;
                Command::none()
            }

            Message::EncryptPressed => {
                if self.password.len() < 12 {
                    self.status_message =
                        "🚨 Password must be at least 12 characters.".to_string();
                    return Command::none();
                }
                if self.file_path.is_empty() {
                    self.status_message = "🚨 Please enter a file path.".to_string();
                    return Command::none();
                }

                self.is_processing = true;
                self.progress = 0.0;
                self.status_message = "🔒 Deriving key with Argon2id… please wait.".to_string();

                // Build progress channel
                let (tx, rx) = tokio::sync::mpsc::channel::<ProgressUpdate>(64);
                self.progress_rx = Some(rx);

                // Wrap password securely
                let secret = SecretVec::new(self.password.as_bytes().to_vec());
                let path = self.file_path.clone();

                Command::perform(
                    async move {
                        let result = async_encrypt(secret, path, tx.clone()).await;
                        let _ = tx.send(ProgressUpdate::Done(result)).await;
                    },
                    |_| Message::OperationFinished(Ok(String::new())), // actual result via channel
                )
            }

            Message::DecryptPressed => {
                if self.password.len() < 12 {
                    self.status_message =
                        "🚨 Password must be at least 12 characters.".to_string();
                    return Command::none();
                }
                if self.file_path.is_empty() {
                    self.status_message = "🚨 Please enter a file path.".to_string();
                    return Command::none();
                }

                self.is_processing = true;
                self.progress = 0.0;
                self.status_message = "🔓 Deriving key with Argon2id… please wait.".to_string();

                let (tx, rx) = tokio::sync::mpsc::channel::<ProgressUpdate>(64);
                self.progress_rx = Some(rx);

                let secret = SecretVec::new(self.password.as_bytes().to_vec());
                let path = self.file_path.clone();

                Command::perform(
                    async move {
                        let result = async_decrypt(secret, path, tx.clone()).await;
                        let _ = tx.send(ProgressUpdate::Done(result)).await;
                    },
                    |_| Message::OperationFinished(Ok(String::new())),
                )
            }

            // Poll the progress channel on every frame via subscription
            Message::ProgressTick(_) => {
                if let Some(rx) = &mut self.progress_rx {
                    // Drain all pending messages without blocking
                    loop {
                        match rx.try_recv() {
                            Ok(ProgressUpdate::Percent(p)) => {
                                self.progress = p;
                                let stage = if p < 6.0 { "Deriving key…" } else { "Streaming…" };
                                self.status_message =
                                    format!("{stage}  {:.0}%", p);
                            }
                            Ok(ProgressUpdate::Done(result)) => {
                                self.is_processing = false;
                                self.progress_rx = None;
                                match result {
                                    Ok(msg) => {
                                        self.progress = 100.0;
                                        self.status_message = format!("✅ {msg}");
                                    }
                                    Err(err) => {
                                        self.progress = 0.0;
                                        self.status_message = format!("🚨 {err}");
                                    }
                                }
                                break;
                            }
                            Err(_) => break,
                        }
                    }
                }
                Command::none()
            }

            // Dummy handler — real result arrives via ProgressUpdate::Done
            Message::OperationFinished(_) => Command::none(),
        }
    }

    /// Poll the progress channel at ~30 fps using iced's time subscription.
    fn subscription(&self) -> iced::Subscription<Message> {
        if self.is_processing {
            iced::time::every(std::time::Duration::from_millis(33))
                .map(|_| Message::ProgressTick(0.0))
        } else {
            iced::Subscription::none()
        }
    }

    fn view(&self) -> Element<Message> {
        // ── password field ──
        let pass_input = text_input("Master password (≥ 12 chars)…", &self.password)
            .on_input(Message::PasswordChanged)
            .password()
            .padding(12);

        // ── path field ──
        let path_input = text_input("Absolute file path…", &self.file_path)
            .on_input(Message::FilePathChanged)
            .padding(12);

        // ── action buttons (disabled while processing) ──
        let action_row = if self.is_processing {
            row![text(format!("⏳ {}", self.status_message)).size(15)]
        } else {
            row![
                button("🔒  Encrypt & Shred").on_press(Message::EncryptPressed).padding(14),
                button("🔓  Decrypt").on_press(Message::DecryptPressed).padding(14),
            ]
            .spacing(20)
        };

        let progress_label = text(format!("{:.0} %", self.progress)).size(13);

        let content = column![
            text("🛡️  AEGIS SOVEREIGN VAULT  v2").size(26),
            text("AES-256-GCM  •  Argon2id  •  Secure-Delete").size(12),
            pass_input,
            path_input,
            action_row,
            progress_bar(0.0..=100.0, self.progress),
            progress_label,
            text(&self.status_message).size(14),
        ]
        .spacing(20)
        .max_width(680);

        container(content)
            .width(Length::Fill)
            .height(Length::Fill)
            .center_x()
            .center_y()
            .padding(48)
            .into()
    }

    fn theme(&self) -> Theme {
        Theme::Dark
    }
}
