use aes_gcm::{
    aead::stream::{EncryptorBE32, DecryptorBE32},
    Aes256Gcm, KeyInit
};
use rand::RngCore;
use zeroize::Zeroize;
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use std::fs::File;
use std::io::{Read, Write};
use std::path::PathBuf;

use iced::{
    executor, Application, Command, Element, Length, Settings, Theme,
    widget::{button, column, container, row, text, text_input, progress_bar},
};

const PBKDF2_ITERATIONS: u32 = 350_000;
const BUFFER_SIZE: usize = 64 * 1024; // 64KB

#[derive(Zeroize)]
#[zeroize(drop)]
struct ProtectedBuffer {
    data: Vec<u8>,
}

#[derive(Zeroize)]
#[zeroize(drop)]
pub struct AegisMasterKey {
    pub key_bytes: [u8; 32],
}

fn derive_secure_key(password: &[u8], salt: &[u8], iterations: u32) -> AegisMasterKey {
    let mut derived_key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(password, salt, iterations, &mut derived_key);
    AegisMasterKey { key_bytes: derived_key }
}

// تعديل توقيع الدوال الخلفية لترجع النتيجة مباشرة متوافقة مع الـ Type System
async fn async_encrypt(password: String, path_str: String) -> Result<String, String> {
    let input_path = PathBuf::from(&path_str);
    let mut source_file = File::open(&input_path).map_err(|e| e.to_string())?;
    let total_file_size = source_file.metadata().map_err(|e| e.to_string())?.len();
    
    let mut output_path = input_path.clone();
    let mut os_string = output_path.into_os_string();
    os_string.push(".aegis");
    let final_output_path = PathBuf::from(os_string);
    
    let mut dest_file = File::create(&final_output_path).map_err(|e| e.to_string())?;

    let mut salt_bytes = [0u8; 16];
    let mut nonce_bytes = [0u8; 7]; 
    rand::thread_rng().fill_bytes(&mut salt_bytes);
    rand::thread_rng().fill_bytes(&mut nonce_bytes);

    dest_file.write_all(&salt_bytes).map_err(|e| e.to_string())?;
    dest_file.write_all(&nonce_bytes).map_err(|e| e.to_string())?;
    dest_file.write_all(&PBKDF2_ITERATIONS.to_be_bytes()).map_err(|e| e.to_string())?;

    let mut password_container = ProtectedBuffer { data: password.into_bytes() };
    let my_crypto_key = derive_secure_key(&password_container.data, &salt_bytes, PBKDF2_ITERATIONS);
    
    let aead = Aes256Gcm::new_from_slice(&my_crypto_key.key_bytes)
        .map_err(|_| "Key Initialization Failed".to_string())?;

    let mut encryptor = EncryptorBE32::from_aead(aead, (&nonce_bytes).into());
    let mut buffer = [0u8; BUFFER_SIZE];
    let mut total_bytes_processed = 0u64;

    loop {
        let read_count = source_file.read(&mut buffer).map_err(|e| e.to_string())?;
        if read_count == 0 { break; }

        total_bytes_processed += read_count as u64;

        if total_bytes_processed >= total_file_size {
            let ciphertext = encryptor.encrypt_last(&buffer[..read_count])
                .map_err(|_| "Encryption Finalization Failed".to_string())?;
            dest_file.write_all(&ciphertext).map_err(|e| e.to_string())?;
            break;
        } else {
            let ciphertext = encryptor.encrypt_next(&buffer[..read_count])
                .map_err(|_| "Encryption Processing Failed".to_string())?;
            dest_file.write_all(&ciphertext).map_err(|e| e.to_string())?;
        }
    }
    
    Ok(format!("Vault generated at: {:?}", final_output_path))
}

async fn async_decrypt(password: String, path_str: String) -> Result<String, String> {
    let input_path = PathBuf::from(&path_str);
    let mut encrypted_file = File::open(&input_path).map_err(|e| e.to_string())?;
    let total_file_size = encrypted_file.metadata().map_err(|e| e.to_string())?.len();

    let mut salt_bytes = [0u8; 16];
    let mut nonce_bytes = [0u8; 7];
    let mut iterations_bytes = [0u8; 4];

    encrypted_file.read_exact(&mut salt_bytes).map_err(|e| e.to_string())?;
    encrypted_file.read_exact(&mut nonce_bytes).map_err(|e| e.to_string())?;
    encrypted_file.read_exact(&mut iterations_bytes).map_err(|e| e.to_string())?;

    let file_iterations = u32::from_be_bytes(iterations_bytes);
    let mut password_container = ProtectedBuffer { data: password.into_bytes() };
    let my_crypto_key = derive_secure_key(&password_container.data, &salt_bytes, file_iterations);
    
    let aead = Aes256Gcm::new_from_slice(&my_crypto_key.key_bytes)
        .map_err(|_| "Key Initialization Failed".to_string())?;

    let mut decryptor = DecryptorBE32::from_aead(aead, (&nonce_bytes).into());

    let decrypted_path = if input_path.extension().map_or(false, |ext| ext == "aegis") {
        input_path.with_extension("")
    } else {
        input_path.with_extension("decrypted")
    };

    let mut dest_file = File::create(&decrypted_path).map_err(|e| e.to_string())?;
    let mut buffer = [0u8; BUFFER_SIZE + 16]; 
    
    let header_size = 16 + 7 + 4;
    let mut total_payload_size = total_file_size - header_size as u64;

    loop {
        let chunk_to_read = std::cmp::min(total_payload_size, (BUFFER_SIZE + 16) as u64) as usize;
        if chunk_to_read == 0 { break; }

        encrypted_file.read_exact(&mut buffer[..chunk_to_read]).map_err(|e| e.to_string())?;
        total_payload_size -= chunk_to_read as u64;

        if total_payload_size == 0 {
            let plaintext = decryptor.decrypt_last(&buffer[..chunk_to_read])
                .map_err(|_| "Wrong password or corrupted file.".to_string())?;
            dest_file.write_all(&plaintext).map_err(|e| e.to_string())?;
            break;
        } else {
            let plaintext = decryptor.decrypt_next(&buffer[..chunk_to_read])
                .map_err(|_| "Decryption Processing Failed".to_string())?;
            dest_file.write_all(&plaintext).map_err(|e| e.to_string())?;
        }
    }

    Ok(format!("Decrypted file saved at: {:?}", decrypted_path))
}

fn main() -> iced::Result {
    // تصحيح استدعاء التشغيل ليتوافق مع الإعدادات الافتراضية للنسخة الحالية
    AegisVaultGui::run(Settings::default())
}

struct AegisVaultGui {
    password: String,
    file_path: String,
    status_message: String,
    progress: f32,
    is_processing: bool,
}

#[derive(Debug, Clone)]
enum Message {
    PasswordChanged(String),
    FilePathChanged(String),
    EncryptPressed,
    DecryptPressed,
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
                status_message: String::from("Ready. Awaiting sovereign command..."),
                progress: 0.0,
                is_processing: false,
            },
            Command::none(),
        )
    }

    fn title(&self) -> String {
        String::from("🛡️ Aegis Sovereign Vault")
    }

    fn update(&mut self, message: Message) -> Command<Message> {
        match message {
            Message::PasswordChanged(pass) => {
                self.password = pass;
                Command::none()
            }
            Message::FilePathChanged(path) => {
                self.file_path = path;
                Command::none()
            }
            Message::EncryptPressed => {
                if self.password.len() < 8 || self.file_path.is_empty() {
                    self.status_message = String::from("🚨 Error: Password >= 8 chars and path cannot be empty.");
                    return Command::none();
                }
                self.is_processing = true;
                self.progress = 50.0;
                self.status_message = String::from("🔒 Streaming core active: Encrypting...");
                
                // حل توافق الـ Types البرمجي الصارم
                let pass = self.password.clone();
                let path = self.file_path.clone();
                Command::perform(async_encrypt(pass, path), Message::OperationFinished)
            }
            Message::DecryptPressed => {
                if self.password.len() < 8 || self.file_path.is_empty() {
                    self.status_message = String::from("🚨 Error: Password >= 8 chars and path cannot be empty.");
                    return Command::none();
                }
                self.is_processing = true;
                self.progress = 50.0;
                self.status_message = String::from("🔓 Streaming core active: Decrypting...");
                
                let pass = self.password.clone();
                let path = self.file_path.clone();
                Command::perform(async_decrypt(pass, path), Message::OperationFinished)
            }
            Message::OperationFinished(result) => {
                self.is_processing = false;
                match result {
                    Ok(msg) => {
                        self.progress = 100.0;
                        self.status_message = format!("✅ {}", msg);
                    }
                    Err(err) => {
                        self.progress = 0.0;
                        self.status_message = format!("🚨 Failure: {}", err);
                    }
                }
                Command::none()
            }
        }
    }

    fn view(&self) -> Element<Message> {
        let pass_input = text_input("Enter Master Password...", &self.password)
            .on_input(Message::PasswordChanged)
            .password()
            .padding(12);

        let path_input = text_input("Enter absolute file path...", &self.file_path)
            .on_input(Message::FilePathChanged)
            .padding(12);

        let action_buttons = if self.is_processing {
            row![text("Processing stream securely. RAM footprint constant...").size(16)]
        } else {
            row![
                button("🔒 Encrypt File").on_press(Message::EncryptPressed).padding(12),
                button("🔓 Decrypt File").on_press(Message::DecryptPressed).padding(12)
            ]
            .spacing(20)
        };

        let content = column![
            text("--- 🛡️ AEGIS SOVEREIGN VAULT ---").size(24),
            text("Sovereign Isolation Cryptographic Core Protocol").size(12),
            pass_input,
            path_input,
            action_buttons,
            progress_bar(0.0..=100.0, self.progress),
            text(&self.status_message).size(15)
        ]
        .spacing(25)
        .max_width(650);

        container(content)
            .width(Length::Fill)
            .height(Length::Fill)
            .center_x()
            .center_y()
            .padding(40)
            .into()
    }

    fn theme(&self) -> Theme {
        Theme::Dark
    }
}

