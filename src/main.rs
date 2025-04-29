use std::collections::HashMap;
use indexmap::IndexMap;
use std::{fs, io};
use std::io::Write;
use std::iter::{Skip, Take};
use std::ops::Index;
use std::vec::IntoIter;
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
use rpassword::read_password;

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
}

struct App {
    enter_mode: EnterMode,
    name_data: String,
    value_data: String,
    should_exit: bool,
    password_manager: PasswordManager,
    passwords: IndexMap<String, String>,
    selection: Option<u32>,
    password: String,
    viewing: Vec<u32>,
    pw_file: String,
    changed: bool,
    error: ErrorDisplay,
    show_pwd: bool,
    ctx_edit: bool
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
    fn new(password: String) -> Result<Self, bool> {
        let pw_file = find_storage_location();
        let pw_man = PasswordManager::init(&pw_file);
        Ok(Self {
            ctx_edit: false,
            show_pwd: false,
            error: ErrorDisplay::None,
            changed: false,
            pw_file,
            viewing: Vec::new(),
            passwords: pw_man.decrypt_all(password.clone())?,
            password,
            selection: None,
            value_data: String::new(),
            name_data: String::new(),
            enter_mode: EnterMode::None,
            should_exit: false,
            password_manager: pw_man,
        })
    }

    fn run(mut self, mut terminal: DefaultTerminal) -> Result<()> {
        while !self.should_exit {
            match self.enter_mode {
                EnterMode::None => {
                    self.ctx_edit = false;
                    terminal.hide_cursor().expect("Failed to hide cursor");
                    terminal.draw(|frame| self.draw_em_none(frame))?;
                    if let Event::Key(key) = event::read()? {
                        self.handle_key_em_none(key);
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
            ErrorDisplay::DuplicateName => "Password with the same name already exists"
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
        let [header_area, top, main, footer_area] = Layout::vertical([
            Constraint::Length(2),
            Constraint::Length(2),
            Constraint::Fill(1),
            Constraint::Length(2),
        ]).areas(area);

        let [left, right] = Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)]).areas(main);
        let mut text = format!("pwstg - Password Storage by MOBSkuchen\nPasswords are at: {}", self.pw_file);
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
        
        let pw_it_1 = selection_window(self.passwords.keys(), i, x);
        let pw_it_2 = selection_window(self.passwords.iter(), i, x);

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

        self.password_manager.add_password(self.password.clone(), name.clone(), &value);
        self.passwords.insert(name, value);
    }

    fn handle_key_em_none(&mut self, key: KeyEvent) {
        if key.kind != KeyEventKind::Press {
            return;
        }

        match key.code {
            KeyCode::Char('+') | KeyCode::Char('a') => self.enter_mode = EnterMode::Name,
            KeyCode::Char('q') => self.should_exit = true,
            KeyCode::Esc => self.select_none(),
            KeyCode::Char('h') | KeyCode::Left => self.select_none(),
            KeyCode::Char('j') | KeyCode::Down => self.select_next(),
            KeyCode::Char('k') | KeyCode::Up => self.select_previous(),
            KeyCode::Char('s') => {
                self.password_manager.to_file(&self.pw_file);
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
                let val = self.passwords.get_index(self.selection.unwrap() as usize).unwrap();

                self.name_data = val.0.to_string();
                self.value_data = val.1.to_string();
                self.enter_mode = EnterMode::Name;

                self.password_manager.passwords.remove(&self.name_data);
                self.passwords.swap_remove_index(self.selection.unwrap() as usize);
                self.changed = true;
            },
            KeyCode::Char('c') if self.selection.is_some() => {
                let val = self.passwords.get_index(self.selection.unwrap() as usize).unwrap();
                copy_to_clipboard(val.1).expect("Failed to copy to clipboard");
            },
            KeyCode::Char('r') if self.selection.is_some() => {
                let val = self.passwords.get_index(self.selection.unwrap() as usize).unwrap();
                self.password_manager.passwords.remove(val.0);
                self.passwords.swap_remove_index(self.selection.unwrap() as usize);
                self.changed = true;
            },
            _ => {}
        }
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
                else if self.passwords.contains_key(&self.name_data) { self.error = ErrorDisplay::DuplicateName }
                else {
                    self.error = ErrorDisplay::None;
                    self.enter_mode = EnterMode::Value
                }
            }
            _ => {}
        }
    }

    fn handle_key_em_value(&mut self, key: KeyEvent) {
        self.show_pwd = false;
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
        if self.passwords.is_empty() {
            self.selection = None;
            return;
        }

        let max_index = self.passwords.len() - 1;
        self.selection = Some(match self.selection {
            Some(i) if i < max_index as u32 => i + 1,
            _ => max_index as u32,
        });
    }

    fn select_previous(&mut self) {
        if self.passwords.is_empty() {
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

fn decrypt_with_password(password: &str, encrypted_text: &EncryptedText) -> Result<String, bool> {
    let key = derive_key(password, encrypted_text.salt.as_slice());
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let nonce_obj = Nonce::from_slice(encrypted_text.nonce.as_slice());

    let decrypted_bytes = cipher.decrypt(nonce_obj, encrypted_text.ciphertext.as_slice()).map_err(|_| {false});

    Ok(String::from_utf8(decrypted_bytes?).expect("Invalid UTF-8"))
}


#[derive(Serialize, Deserialize)]
struct PasswordManager {
    passwords: HashMap<String, EncryptedText>,
    username: String,
}

impl PasswordManager {
    pub fn load_from_file(path: &String) -> Self {
        bincode::deserialize(&fs::read(path).unwrap()).unwrap()
    }

    pub fn to_file(&self, path: &String) {
        fs::write(path, bincode::serialize(self).unwrap()).expect("Failed to write");
    }

    pub fn init(path: &String) -> Self {
        if fs::exists(path).unwrap() { Self::load_from_file(path) }
        else {
            let s = Self {passwords: HashMap::new(), username: whoami::username().unwrap()};
            s.to_file(path);
            s
        }
    }

    pub fn decrypt_all(&self, password: String) -> Result<IndexMap<String, String>, bool> {
        let mut hm = IndexMap::new();
        for pw in self.passwords.iter() {
            hm.insert(pw.0.to_owned(), decrypt_with_password(&password, pw.1)?);
        }
        Ok(hm)
    }

    pub fn add_password(&mut self, password: String, name: String, value: &str) {
        let enc = encrypt_with_password(value, &password);
        self.passwords.insert(name, enc);
    }
}

#[derive(Serialize, Deserialize)]
struct EncryptedText {
    salt: [u8; 16],
    nonce: [u8; 12],
    ciphertext: Vec<u8>
}

fn prompt_password() -> io::Result<String> {
    io::stdout().flush()?;
    let password = read_password()?;
    Ok(password)
}

fn main() -> Result<()> {
    print!("Enter password to read password-storage at {}\n> ", find_storage_location());
    let password = prompt_password();
    if password.is_err() {
        println!("Aborted");
        return Ok(())
    }
    color_eyre::install()?;
    let terminal = ratatui::init();
    let app_result = App::new(password?);
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