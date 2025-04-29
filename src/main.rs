use std::collections::HashMap;
use std::fs;
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use chacha20poly1305::aead::{Aead, KeyInit, OsRng, rand_core::RngCore};
use argon2::{Argon2, PasswordHasher};
use argon2::password_hash::{SaltString, PasswordHash, PasswordVerifier, rand_core::OsRng as PasswordOsRng};
use hex;
use bincode;
use serde::{Deserialize, Serialize};

use color_eyre::Result;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind};
use ratatui::buffer::Buffer;
use ratatui::layout::{Constraint, Flex, Layout, Rect};
use ratatui::style::palette::tailwind::{BLUE, GREEN, SLATE};
use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, Clear, HighlightSpacing, List, ListItem, ListState, Padding, Paragraph, StatefulWidget, Widget, Wrap};
use ratatui::{symbols, DefaultTerminal, Frame};

const TODO_HEADER_STYLE: Style = Style::new().fg(SLATE.c100).bg(BLUE.c800);
const NORMAL_ROW_BG: Color = SLATE.c950;
const ALT_ROW_BG_COLOR: Color = SLATE.c900;
const SELECTED_STYLE: Style = Style::new().bg(SLATE.c800).add_modifier(Modifier::BOLD);
const TEXT_FG_COLOR: Color = SLATE.c200;
const COMPLETED_TEXT_FG_COLOR: Color = GREEN.c500;

enum EnterMode {
    None,
    Name,
    Value
}

struct App {
    enter_mode: EnterMode,
    name_data: String,
    value_data: String,
    should_exit: bool,
    password_manager: PasswordManager,
    selection: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum Status {
    Todo,
    Completed,
}

impl Default for App {
    fn default() -> Self {
        Self {
            value_data: String::new(),
            name_data: String::new(),
            enter_mode: EnterMode::None,
            should_exit: false,
            password_manager: PasswordManager::init(".pw_stg".to_string()),
        }
    }
}

fn popup_area(area: Rect, percent_x: u16, percent_y: u16) -> Rect {
    let vertical = Layout::vertical([Constraint::Percentage(percent_y)]).flex(Flex::Center);
    let horizontal = Layout::horizontal([Constraint::Percentage(percent_x)]).flex(Flex::Center);
    let [area] = vertical.areas(area);
    let [area] = horizontal.areas(area);
    area
}

impl App {
    fn run(mut self, mut terminal: DefaultTerminal) -> Result<()> {
        while !self.should_exit {
            match self.enter_mode {
                EnterMode::None => {
                    terminal.draw(|frame| frame.render_widget(&mut self, frame.area()))?;
                    if let Event::Key(key) = event::read()? {
                        self.handle_key_em_none(key);
                    }
                }
                EnterMode::Name => {
                    terminal.draw(|frame| self.draw_em_name(frame))?;
                    if let Event::Key(key) = event::read()? {
                        self.handle_key_em_name(key);
                    }
                }
                EnterMode::Value => {
                    terminal.draw(|frame| self.draw_em_value(frame))?;
                    if let Event::Key(key) = event::read()? {
                        self.handle_key_em_value(key);
                    }
                }
            }
        }
        Ok(())
    }

    fn draw_em_name(&self, frame: &mut Frame) {
        let area = frame.area();

        let vertical = Layout::vertical([Constraint::Percentage(20), Constraint::Percentage(80)]);
        let [instructions, content] = vertical.areas(area);
        
        let paragraph = Paragraph::new("Press ESC to go back".slow_blink())
            .centered()
            .wrap(Wrap { trim: true });
        frame.render_widget(paragraph, instructions);

        let block = Paragraph::new(&*self.name_data).block(Block::bordered().title("Enter Password Name"));
        let area = popup_area(area, 60, 20);
        frame.render_widget(block, area);
    }

    fn draw_em_value(&self, frame: &mut Frame) {
        let area = frame.area();

        let vertical = Layout::vertical([Constraint::Percentage(20), Constraint::Percentage(80)]);
        let [instructions, content] = vertical.areas(area);

        let paragraph = Paragraph::new("Press ESC to go back".slow_blink())
            .centered()
            .wrap(Wrap { trim: true });
        frame.render_widget(paragraph, instructions);
        
        let block = Paragraph::new("*".repeat(self.value_data.len())).block(Block::bordered().title("Enter Password"));
        let area = popup_area(area, 60, 20);
        frame.render_widget(block, area);
    }

    fn handle_key_em_none(&mut self, key: KeyEvent) {
        if key.kind != KeyEventKind::Press {
            return;
        }
        match key.code {
            KeyCode::Char('+') => self.enter_mode = EnterMode::Name,
            KeyCode::Char('q') | KeyCode::Esc => self.should_exit = true,
            KeyCode::Char('h') | KeyCode::Left => self.select_none(),
            KeyCode::Char('j') | KeyCode::Down => self.select_next(),
            KeyCode::Char('k') | KeyCode::Up => self.select_previous(),
            KeyCode::Char('g') | KeyCode::Home => self.select_first(),
            KeyCode::Char('G') | KeyCode::End => self.select_last(),
            KeyCode::Char('l') | KeyCode::Right | KeyCode::Enter => {
                self.toggle_status();
            }
            _ => {}
        }
    }

    fn handle_key_em_name(&mut self, key: KeyEvent) {
        if key.kind != KeyEventKind::Press {
            return;
        }
        
        match key.code {
            KeyCode::Esc => self.enter_mode = EnterMode::None,
            KeyCode::Backspace => {
                self.name_data.pop();
            }
            KeyCode::Char(c) => {
                self.name_data.push(c);
            }
            KeyCode::Enter => {
                self.enter_mode = EnterMode::Value
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
            KeyCode::Char(c) => {
                self.value_data.push(c);
            }
            KeyCode::Enter => {
                self.enter_mode = EnterMode::None
                // TODO: Add pushing and shit
            }
            _ => {}
        }
    }

    fn select_none(&mut self) {
        self.selection = None
    }

    fn select_next(&mut self) {
        self.selection = self.selection.and_then(|t| {Some(t+1)}).or(Some(0))
    }
    
    fn select_previous(&mut self) {
        self.selection = self.selection.and_then(|t| {Some(t-1)}).or(Some(0))
    }
}

impl Widget for &mut App {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let [header_area, main_area, footer_area] = Layout::vertical([
            Constraint::Length(2),
            Constraint::Fill(1),
            Constraint::Length(1),
        ])
            .areas(area);

        let [list_area, item_area] =
            Layout::vertical([Constraint::Fill(1), Constraint::Fill(1)]).areas(main_area);

        App::render_header(header_area, buf);
        App::render_footer(footer_area, buf);
        self.render_list(list_area, buf);
        self.render_selected_item(item_area, buf);
    }
}

/// Rendering logic for the app
impl App {
    fn render_header(area: Rect, buf: &mut Buffer) {
        Paragraph::new("Ratatui Todo List Example")
            .bold()
            .centered()
            .render(area, buf);
    }

    fn render_footer(area: Rect, buf: &mut Buffer) {
        Paragraph::new("Use ↓↑ to move, ← to unselect, → to change status, g/G to go top/bottom.")
            .centered()
            .render(area, buf);
    }

    fn render_list(&mut self, area: Rect, buf: &mut Buffer) {
        let block = Block::new()
            .title(Line::raw("Passwords").centered())
            .borders(Borders::TOP)
            .border_set(symbols::border::EMPTY)
            .border_style(TODO_HEADER_STYLE)
            .bg(NORMAL_ROW_BG);

        // Iterate through all elements in the `items` and stylize them.
        let items: Vec<ListItem> = self
            .todo_list
            .items
            .iter()
            .enumerate()
            .map(|(i, todo_item)| {
                let color = alternate_colors(i);
                ListItem::from(todo_item).bg(color)
            })
            .collect();

        // Create a List from all list items and highlight the currently selected one
        let list = List::new(items)
            .block(block)
            .highlight_style(SELECTED_STYLE)
            .highlight_symbol(">")
            .highlight_spacing(HighlightSpacing::Always);

        // We need to disambiguate this trait method as both `Widget` and `StatefulWidget` share the
        // same method name `render`.
        StatefulWidget::render(list, area, buf, &mut self.todo_list.state);
    }

    fn render_selected_item(&self, area: Rect, buf: &mut Buffer) {
        // We get the info depending on the item's state.
        let info = if let Some(i) = self.todo_list.state.selected() {
            match self.todo_list.items[i].status {
                Status::Completed => format!("✓ DONE: {}", self.todo_list.items[i].info),
                Status::Todo => format!("☐ TODO: {}", self.todo_list.items[i].info),
            }
        } else {
            "Nothing selected...".to_string()
        };

        // We show the list item's info under the list in this paragraph
        let block = Block::new()
            .title(Line::raw("TODO Info").centered())
            .borders(Borders::TOP)
            .border_set(symbols::border::EMPTY)
            .border_style(TODO_HEADER_STYLE)
            .bg(NORMAL_ROW_BG)
            .padding(Padding::horizontal(1));

        // We can now render the item info
        Paragraph::new(info)
            .block(block)
            .fg(TEXT_FG_COLOR)
            .wrap(Wrap { trim: false })
            .render(area, buf);
    }
}

const fn alternate_colors(i: usize) -> Color {
    if i % 2 == 0 {
        NORMAL_ROW_BG
    } else {
        ALT_ROW_BG_COLOR
    }
}

impl From<&String> for ListItem<'_> {
    fn from(value: &String) -> Self {
        let line = match value.status {
            Status::Todo => Line::styled(format!(" ☐ {}", value.todo), TEXT_FG_COLOR),
            Status::Completed => {
                Line::styled(format!(" ✓ {}", value.todo), COMPLETED_TEXT_FG_COLOR)
            }
        };
        ListItem::new(line)
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
    // Generate random salt
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);

    // Derive key
    let key = derive_key(password, &salt);

    // Create cipher
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));

    // Generate random nonce
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let nonce_obj = Nonce::from_slice(&nonce);

    // Encrypt
    let ciphertext = cipher.encrypt(nonce_obj, plaintext.as_bytes())
        .expect("Encryption failure");

    EncryptedText {
        salt,
        ciphertext,
        nonce
    }
}

fn decrypt_with_password(password: &str, encrypted_text: &EncryptedText) -> String {
    let key = derive_key(password, encrypted_text.salt.as_slice());
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let nonce_obj = Nonce::from_slice(encrypted_text.nonce.as_slice());

    let decrypted_bytes = cipher.decrypt(nonce_obj, encrypted_text.ciphertext.as_slice())
        .expect("Decryption failure");

    String::from_utf8(decrypted_bytes).expect("Invalid UTF-8")
}


#[derive(Serialize, Deserialize)]
struct PasswordManager {
    passwords: HashMap<String, EncryptedText>,
    username: String,
}

impl PasswordManager {
    pub fn load_from_file(path: String) -> Self {
        bincode::deserialize(&*fs::read(path).unwrap()).unwrap()
    }

    pub fn to_file(&self, path: String) {
        fs::write(path, bincode::serialize(self).unwrap()).expect("Failed to write");
    }

    pub fn init(path: String) -> Self {
        if fs::exists(&path).unwrap() { Self::load_from_file(path) }
        else {
            let s = Self {passwords: HashMap::new(), username: whoami::username().unwrap()};
            s.to_file(path);
            s
        }
    }
}

#[derive(Serialize, Deserialize)]
struct EncryptedText {
    salt: [u8; 16],
    nonce: [u8; 12],
    ciphertext: Vec<u8>
}

fn main() -> Result<()> {
    color_eyre::install()?;
    let terminal = ratatui::init();
    let app_result = App::default().run(terminal);
    ratatui::restore();
    app_result
}


// fn main() {
//     let path = format!("/home/{}/.pwstg", whoami::username().unwrap());
//     let pw_man = PasswordManager::init(path);
// }
//