use indexmap::IndexMap;
use std::{fs, io};
use std::io::Write;
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use chacha20poly1305::aead::{Aead, KeyInit, OsRng, rand_core::RngCore};
use argon2::{Argon2};
use serde::{Deserialize, Serialize};
use color_eyre::Result;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind};
use ratatui::layout::{Constraint, Flex, Layout, Rect};
use ratatui::style::{Color, Style, Stylize};
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Wrap};
use ratatui::{symbols, DefaultTerminal, Frame};
use arboard::Clipboard;
use clap::Arg;
use clap::ValueHint::AnyPath;
use rpassword::read_password;
use crate::Error::{InaccessibleClipboard, Other, RemovalFailed, WrongPassword, StorageFileNotFound, StorageFileFormat};

pub const NAME: &str = env!("CARGO_PKG_NAME");
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const DESCRIPTION: &str = env!("CARGO_PKG_DESCRIPTION");

#[derive(Debug)]
enum Error {
    RemovalFailed,
    InaccessibleClipboard,
    WrongPassword,
    StorageFileNotFound(String),
    StorageFileFormat(String),
    Other(io::Error),
    WriteFailed
}

fn find_storage_location() -> String {
    let mut base_dir = dirs::data_local_dir().expect("Failed to find local app data path");
    base_dir.push(".pw_stg");
    base_dir.to_str().unwrap().to_string()
}

fn copy_to_clipboard(text: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut clipboard = Clipboard::new()?;
    clipboard.set_text(text.to_string())?;
    Ok(())
}

enum EnterMode {
    None,
    Name,
    Value
}

enum ErrorDisplay {
    None,
    EmptyField,
    DuplicateName,
    Failed2Write
}

struct PasswordContext {
    password_manager: PasswordHolderInterface,
    pw_file: String,
    password: String
}

impl PasswordContext {
    
    pub fn auto(password: String, pw_file: String) -> Result<Self, Error> {
        let password_manager = PasswordHolderInterface::init(&pw_file, &password)?;
        Ok(Self {password_manager, pw_file, password})
    }
}

struct App {
    enter_mode: EnterMode,
    name_data: String,
    value_data: String,
    should_exit: bool,
    selection: Option<u32>,
    viewing: Vec<u32>,
    changed: bool,
    error: ErrorDisplay,
    show_pwd: bool,
    ctx_edit: bool,
    pw_context: PasswordContext,
}

fn popup_area(area: Rect) -> Rect {
    let vertical = Layout::vertical([Constraint::Length(4)]).flex(Flex::Center);
    let horizontal = Layout::horizontal([Constraint::Percentage(70)]).flex(Flex::Center);
    let [area] = vertical.areas(area);
    let [area] = horizontal.areas(area);
    area
}

fn selection_window<T>(
    iter: impl IntoIterator<Item = T>,
    selected: usize,
    max_height: usize,
) -> Vec<T> {
    let vec: Vec<T> = iter.into_iter().collect();
    let total = vec.len();

    if total == 0 || max_height == 0 {
        return vec![];
    }

    let half_height = max_height / 2;

    let mut start = selected.saturating_sub(half_height);
    let mut end = start + max_height;

    if end > total {
        end = total;
        start = end.saturating_sub(max_height);
    }

    Vec::from_iter(vec.into_iter().skip(start).take(end - start))
}



impl App {
    fn new(pw_context: PasswordContext) -> Result<Self, bool> {
        Ok(Self {
            ctx_edit: false,
            show_pwd: false,
            error: ErrorDisplay::None,
            changed: false,
            viewing: Vec::new(),
            pw_context,
            selection: None,
            value_data: String::new(),
            name_data: String::new(),
            enter_mode: EnterMode::None,
            should_exit: false,
        })
    }

    fn run(mut self, mut terminal: DefaultTerminal) -> io::Result<()> {
        while !self.should_exit {
            match self.enter_mode {
                EnterMode::None => {
                    self.ctx_edit = false;
                    terminal.hide_cursor().expect("Failed to hide cursor");
                    terminal.draw(|frame| self.draw_em_none(frame))?;
                    if let Event::Key(key) = event::read()? {
                        if self.handle_key_em_none(key).is_err() {
                            self.error = ErrorDisplay::Failed2Write // Only error that can come from here
                        }
                    }
                }
                EnterMode::Name => {
                    terminal.show_cursor().expect("Failed to show cursor");
                    terminal.draw(|frame| self.draw_em_name(frame))?;
                    if let Event::Key(key) = event::read()? {
                        self.handle_key_em_name(key);
                    }
                }
                EnterMode::Value => {
                    terminal.show_cursor().expect("Failed to show cursor");
                    terminal.draw(|frame| self.draw_em_value(frame))?;
                    if let Event::Key(key) = event::read()? {
                        self.handle_key_em_value(key);
                    } else {
                        self.show_pwd = false;
                    }
                }
            }
        }
        Ok(())
    }

    fn draw_error(&self, frame: &mut Frame, area: Rect) {
        let text = match self.error {
            ErrorDisplay::None => return,
            ErrorDisplay::EmptyField => "This field may not be empty",
            ErrorDisplay::DuplicateName => "Password with the same name already exists",
            ErrorDisplay::Failed2Write => "Failed to write passwords"
        };

        let paragraph = Paragraph::new(text.rapid_blink().red()).centered();
        frame.render_widget(paragraph, area);
    }

    fn draw_em_name(&self, frame: &mut Frame) {
        let area = frame.area();

        let [instructions, ed] = Layout::vertical([Constraint::Length(1), Constraint::Length(2)]).areas(area);
        self.draw_error(frame, ed);

        let paragraph = Paragraph::new("Press ESC to go back".slow_blink())
            .centered()
            .wrap(Wrap { trim: true });
        frame.render_widget(paragraph, instructions);

        let block = Paragraph::new(&*self.name_data).block(Block::bordered().title("Enter Password Name"));
        let area = popup_area(area);
        frame.render_widget(block, area);
    }

    fn draw_em_value(&self, frame: &mut Frame) {
        let area = frame.area();

        let [instructions, ed] = Layout::vertical([Constraint::Length(1), Constraint::Length(2)]).areas(area);
        self.draw_error(frame, ed);

        let paragraph = Paragraph::new("Press ESC to go back".slow_blink())
            .centered()
            .wrap(Wrap { trim: true });
        frame.render_widget(paragraph, instructions);
        
        let block = Paragraph::new(if self.show_pwd { self.value_data.to_owned() } else { "*".repeat(self.value_data.len()) }).block(Block::bordered().title("Enter Password"));
        let area = popup_area(area);
        frame.render_widget(block, area);
    }

    fn draw_em_none(&self, frame: &mut Frame) {
        let area = frame.area();
        let [header_area, ed, top, main, footer_area] = Layout::vertical([
            Constraint::Length(2),
            Constraint::Length(1),
            Constraint::Length(2),
            Constraint::Fill(1),
            Constraint::Length(2),
        ]).areas(area);

        self.draw_error(frame, ed);

        let [left, right] = Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)]).areas(main);
        let mut text = format!("pwstg - Password Storage by MOBSkuchen\nPasswords for {} are at: {}", self.pw_context.password_manager.username, self.pw_context.pw_file);
        if self.changed {
            text = format!("{text} <unsaved changes>");
        }
        frame.render_widget(Paragraph::new(text).bold().centered(), header_area);
        frame.render_widget(Paragraph::new("Use ↓↑ to move, + / a to add one, v to view / hide, TAB to show all\nc to copy password, e to edit, r to remove, s to save, ESC to unselect, q to quit.").centered(), footer_area);

        let i = self.selection.unwrap_or(0) as usize;
        let x = left.height as usize;

        let block = Block::new()
            .title(Line::raw("Passwords").left_aligned())
            .borders(Borders::BOTTOM)
            .border_set(symbols::border::ROUNDED);

        frame.render_widget(block, top);

        let pw_it_1 = selection_window(self.pw_context.password_manager.passwords.keys(), i, x);
        let pw_it_2 = selection_window(self.pw_context.password_manager.passwords.iter(), i, x);

        let items: Vec<ListItem> = pw_it_1.iter()
            .enumerate()
            .map(|(i, pw_name)| {
                if self.selection.is_some_and(|x| {x==i as u32}) {
                    ListItem::new(Line::styled(format!("> {pw_name}"), Style::from(Color::Cyan)))
                } else {
                    ListItem::new(Line::styled(*pw_name, Style::default()))
                }
            })
            .collect();

        frame.render_widget(List::new(items), left);

        let items: Vec<ListItem> = pw_it_2.iter()
            .enumerate()
            .map(|(i, pw_name)| {
                let pw = if self.show_pwd || self.viewing.contains(&(i as u32)) { pw_name.1.to_owned() } else { "*".repeat(pw_name.1.len()) };
                if self.selection.is_some_and(|x| {x==i as u32}) {
                    ListItem::new(Line::styled(pw, Style::from(Color::Cyan)))
                } else {
                    ListItem::new(Line::styled(pw, Style::default()))
                }
            })
            .collect();

        frame.render_widget(List::new(items), right);
    }

    fn add_password(&mut self) {
        self.changed = true;

        let name = self.name_data.clone();
        let value = self.value_data.clone();

        self.name_data = String::new();
        self.value_data = String::new();

        self.pw_context.password_manager.add_password(name, value);
    }

    fn handle_key_em_none(&mut self, key: KeyEvent) -> Result<(), Error> {
        if key.kind != KeyEventKind::Press {
            return Ok(());
        }

        match key.code {
            KeyCode::Char('+') | KeyCode::Char('a') => self.enter_mode = EnterMode::Name,
            KeyCode::Char('q') => self.should_exit = true,
            KeyCode::Esc => self.select_none(),
            KeyCode::Char('h') | KeyCode::Left => self.select_none(),
            KeyCode::Char('j') | KeyCode::Down => self.select_next(),
            KeyCode::Char('k') | KeyCode::Up => self.select_previous(),
            KeyCode::Char('s') => {
                self.pw_context.password_manager.save(&self.pw_context.pw_file, &self.pw_context.password)?;
                self.changed = false;
            },
            KeyCode::Tab => {
                self.show_pwd = !self.show_pwd;
            }
            KeyCode::Char('v') if self.selection.is_some() => {
                let i = self.selection.unwrap();
                if let Some(index) = self.viewing.iter().position(|value| *value == i) {
                    self.viewing.swap_remove(index);
                } else {
                    self.viewing.push(i);
                }
            },
            KeyCode::Char('e') if self.selection.is_some() => {
                self.ctx_edit = true;
                let val = self.pw_context.password_manager.passwords.get_index(self.selection.unwrap() as usize).unwrap();

                self.name_data = val.0.to_string();
                self.value_data = val.1.to_string();
                self.enter_mode = EnterMode::Name;

                self.pw_context.password_manager.passwords.swap_remove_index(self.selection.unwrap() as usize);
                self.changed = true;
            },
            KeyCode::Char('c') if self.selection.is_some() => {
                let val = self.pw_context.password_manager.passwords.get_index(self.selection.unwrap() as usize).unwrap();
                copy_to_clipboard(val.1).expect("Failed to copy to clipboard");
            },
            KeyCode::Char('r') if self.selection.is_some() => {
                self.pw_context.password_manager.passwords.swap_remove_index(self.selection.unwrap() as usize);
                self.changed = true;
            },
            _ => {}
        }
        Ok(())
    }

    fn handle_key_em_name(&mut self, key: KeyEvent) {
        self.show_pwd = false;
        if key.kind != KeyEventKind::Press {
            return;
        }
        
        match key.code {
            KeyCode::Esc => {
                if self.ctx_edit { self.add_password() }
                self.name_data = String::new();
                self.value_data = String::new();
                self.enter_mode = EnterMode::None
            },
            KeyCode::Backspace => {
                self.name_data.pop();
            }
            KeyCode::Char(c) => {
                self.name_data.push(c);
            }
            KeyCode::Enter => {
                if self.name_data.is_empty() { self.error = ErrorDisplay::EmptyField }
                else if self.pw_context.password_manager.passwords.contains_key(&self.name_data) { self.error = ErrorDisplay::DuplicateName }
                else {
                    self.error = ErrorDisplay::None;
                    self.enter_mode = EnterMode::Value
                }
            }
            _ => {}
        }
    }

    fn handle_key_em_value(&mut self, key: KeyEvent) {
        if key.kind != KeyEventKind::Press {
            return;
        }

        match key.code {
            KeyCode::Esc => self.enter_mode = EnterMode::Name,
            KeyCode::Backspace => {
                self.value_data.pop();
            }
            KeyCode::Tab => {
                self.show_pwd = !self.show_pwd;
            }
            KeyCode::Char(c) => {
                self.value_data.push(c)
            }
            KeyCode::Enter => {
                if self.value_data.is_empty() { self.error = ErrorDisplay::EmptyField }
                else {
                    self.error = ErrorDisplay::None;
                    self.enter_mode = EnterMode::None
                }
                self.add_password()
            }
            _ => {}
        }
    }

    fn select_none(&mut self) {
        self.selection = None
    }

    fn select_next(&mut self) {
        if self.pw_context.password_manager.passwords.is_empty() {
            self.selection = None;
            return;
        }

        let max_index = self.pw_context.password_manager.passwords.len() - 1;
        self.selection = Some(match self.selection {
            Some(i) if i < max_index as u32 => i + 1,
            _ => max_index as u32,
        });
    }

    fn select_previous(&mut self) {
        if self.pw_context.password_manager.passwords.is_empty() {
            self.selection = None;
            return;
        }

        self.selection = Some(match self.selection {
            Some(i) if i > 0 => i - 1,
            _ => 0,
        });
    }
}

fn derive_key(password: &str, salt: &[u8]) -> [u8; 32] {
    let argon2 = Argon2::default();

    let mut key = [0u8; 32];
    argon2.hash_password_into(password.as_bytes(), salt, &mut key)
        .expect("Key derivation failed");
    key
}

fn encrypt_with_password(plaintext: &str, password: &str) -> EncryptedText {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let key = derive_key(password, &salt);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let nonce_obj = Nonce::from_slice(&nonce);
    let ciphertext = cipher.encrypt(nonce_obj, plaintext.as_bytes())
        .expect("Encryption failure");

    EncryptedText {
        salt,
        ciphertext,
        nonce
    }
}

fn decrypt_with_password(password: &str, encrypted_text: &EncryptedText) -> Result<String, Error> {
    let key = derive_key(password, encrypted_text.salt.as_slice());
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let nonce_obj = Nonce::from_slice(encrypted_text.nonce.as_slice());

    let decrypted_bytes = cipher.decrypt(nonce_obj, encrypted_text.ciphertext.as_slice()).map_err(|_| {WrongPassword});

    Ok(String::from_utf8(decrypted_bytes?).expect("Invalid UTF-8"))
}

#[derive(Serialize, Deserialize)]
struct PwEntry ((EncryptedText, EncryptedText));

impl PwEntry {
    pub fn decrypt(&self, key: &str) -> Result<(String, String), Error> {
        Ok((decrypt_with_password(key, &self.0.0)?, decrypt_with_password(key, &self.0.1)?))
    }
    
    pub fn encrypt(key: &str, item: (&String, &String)) -> Self {
        Self((encrypt_with_password(item.0.as_str(), key), encrypt_with_password(item.1.as_str(), key)))
    }
}


#[derive(Serialize, Deserialize)]
struct PasswordStorageHolder {
    passwords: Vec<PwEntry>,
    username: String,
}

struct PasswordHolderInterface {
    pub passwords: IndexMap<String, String>,
    pub username: String,
}

impl PasswordHolderInterface {
    pub fn init(path: &String, key: &str) -> Result<Self, Error> {
        Self::from_enc(PasswordStorageHolder::init(path)?, key)
    }

    pub fn add_password(&mut self, name: String, value: String) {
        self.passwords.insert(name, value);
    }

    pub fn save(&self, path: &String, key: &str) -> Result<(), Error> {
        self.to_enc(key)?.to_file(path)
    }
    
    pub fn from_enc(pw_stg_hld: PasswordStorageHolder, key: &str) -> Result<Self, Error> {
        let mut passwords: IndexMap<String, String> = IndexMap::new();
        for entry in pw_stg_hld.passwords {
            let dec = entry.decrypt(key)?;
            passwords.insert(dec.0, dec.1);
        }
        Ok(Self { passwords, username: pw_stg_hld.username })
    }

    pub fn to_enc(&self, key: &str) -> Result<PasswordStorageHolder, Error> {
        let passwords = Vec::from_iter(self.passwords.iter().map(|x| {PwEntry::encrypt(key, x)}));
        Ok(PasswordStorageHolder { passwords, username: self.username.clone() })
    }
}

impl PasswordStorageHolder {
    pub fn load_from_file(path: &String) -> Result<Self, Error> {
        bincode::deserialize(&fs::read(path).map_err(|_| {StorageFileNotFound(path.to_owned())})?).map_err(|_| {StorageFileFormat(path.to_owned())})
    }

    pub fn to_file(&self, path: &String) -> Result<(), Error> {
        fs::write(path, bincode::serialize(self).unwrap()).map_err(|_| {Error::WriteFailed})
    }

    pub fn init(path: &String) -> Result<Self, Error> {
        if fs::exists(path).unwrap() { Self::load_from_file(path) }
        else {
            let s = Self {passwords: vec![], username: whoami::username().unwrap()};
            s.to_file(path)?;
            Ok(s)
        }
    }
}

#[derive(Serialize, Deserialize)]
struct EncryptedText {
    salt: [u8; 16],
    nonce: [u8; 12],
    ciphertext: Vec<u8>
}

fn prompt_password(loc: &String) -> io::Result<String> {
    print!("Enter password to read password-storage at {}\n> ", loc);
    io::stdout().flush()?;
    let password = read_password()?;
    //  MOVE 2 UP  CLEAR LINE
    print!("\x1B[2A\x1B[K");
    Ok(password)
}

fn windowed_main(pw_ctx: PasswordContext) -> io::Result<()> {
    color_eyre::install().expect("Failed to install color-eyre");
    let terminal = ratatui::init();
    let app_result = App::new(pw_ctx);
    match app_result {
        Ok(app_result) => {
            let app_result = app_result.run(terminal);
            ratatui::restore();
            app_result
        }
        Err(_) => {
            println!("Wrong password!");
            Ok(())
        }
    }
}

fn create_pw_context(matches: &clap::ArgMatches) -> Result<PasswordContext, Error> {
    let location = matches.get_one("stg").map(|t: &String| t.to_owned()).unwrap_or_else(find_storage_location).to_owned();
    let password = matches.get_one("password").map(|t: &String| t.to_owned()).or_else(|| {prompt_password(&location).ok()});
    if password.is_none() {return Err(WrongPassword)}
    PasswordContext::auto(password.unwrap(), location)
}

fn get_main(ctx: PasswordContext, password: &String, mask: bool, copy: bool) -> Result<(), Error> {
    match ctx.password_manager.passwords.get(password) {
        None => {
            println!("The password `{password}` was not found");
        }
        Some(value) => {
            if copy { copy_to_clipboard(value).map_err(|_| InaccessibleClipboard)?; }
            let value = if mask { "*".repeat(value.len()).to_string() } else { value.to_owned() };
            println!("Password: `{password}` => {value}");
        }
    }
    Ok(())
}

fn list_main(ctx: PasswordContext) -> Result<(), Error> {
    for password in ctx.password_manager.passwords {
        println!("Password: `{}` => {}", password.0, "*".repeat(password.1.len()));
    }
    Ok(())
}

fn main2() -> Result<(), Error> {
    let matches = clap::Command::new(NAME)
        .about(DESCRIPTION)
        .version(VERSION)
        .disable_version_flag(true)
        .arg(Arg::new("stg")
            .long("stg")
            .short('s')
            .help("Sets the location of the storage")
            .value_name("location")
            .value_hint(AnyPath)
            .action(clap::ArgAction::Set))
        .arg(Arg::new("get")
            .long("get")
            .short('g')
            .help("Gets a given password")
            .value_name("password-name")
            .action(clap::ArgAction::Set))
        .arg(Arg::new("password")
            .long("password")
            .short('p')
            .help("Sets the password to use, automates auth")
            .value_name("password")
            .action(clap::ArgAction::Set))
        .arg(Arg::new("mask")
            .long("mask")
            .short('m')
            .requires("get")
            .help("Mask (hide) password")
            .action(clap::ArgAction::SetTrue))
        .arg(Arg::new("copy")
            .long("copy")
            .short('c')
            .requires("get")
            .help("Copys the password")
            .action(clap::ArgAction::SetTrue))
        .arg(Arg::new("list")
            .conflicts_with_all(["get", "copy", "mask"])
            .long("list")
            .short('l')
            .help("Lists all given passwords")
            .action(clap::ArgAction::SetTrue))
        .arg(Arg::new("regen")
            .exclusive(true)
            .long("regenerate-stg")
            .help("Deletes the DEFAULT stg file")
            .action(clap::ArgAction::SetTrue))
        .arg(Arg::new("version")
            .short('v')
            .long("version")
            .help("Displays the version")
            .action(clap::ArgAction::Version))
        .get_matches();
    if matches.get_flag("regen") {
        fs::remove_file(find_storage_location()).map_err(|_| RemovalFailed)
    } else {
        let ctx = create_pw_context(&matches)?;
        if matches.contains_id("get") {
            get_main(ctx, matches.get_one("get").unwrap(), matches.get_flag("mask"), matches.get_flag("copy"))
        } else if matches.get_flag("list") {
            list_main(ctx)
        } else {
            windowed_main(ctx).map_err(|e| { Other(e) })
        }
    }
}

fn main() {
    let result = main2();
    if let Err(e) = result {
        match e {
            RemovalFailed =>
                println!("Failed to remove the default storage"),
            InaccessibleClipboard =>
                println!("Could not access your clipboard"),
            WrongPassword =>
                println!("The given password was wrong"),
            StorageFileNotFound(loc) =>
                println!("The storage file was not found at {loc}"),
            StorageFileFormat(loc) => {
                println!("The storage file could not be read at {loc}, because it isn't in the right format");
                println!("It might have been externally modified or created in a previous version of pwstg (before {VERSION})");
                println!("Notably, before a breaking change at V0.3.0");
                println!("You can use `--stg <path>` to set the storage location to somewhere else");
                println!("Or use `--regenerate-stg` to remove the file")
            }
            Other(o) => println!("System error: {}", o),
            Error::WriteFailed => println!("Failed to write password storage file!"),
        }
    }
}