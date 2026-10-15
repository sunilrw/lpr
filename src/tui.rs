use crate::engine::LogEngine;
use crate::parsers::InputFormat;
use anyhow::Result;
use arrow::util::display::array_value_to_string;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table},
    Terminal,
};
use std::io;

pub async fn run_tui(source_path: &str, format: InputFormat) -> Result<()> {
    let engine = LogEngine::new();
    engine.register_source("logs", source_path, format, None).await?;

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut sql_input = String::from("SELECT * FROM logs LIMIT 50");
    let mut status_msg = format!("Loaded `{}` | Enter=Run, Esc=Quit", source_path);
    let mut headers: Vec<String> = Vec::new();
    let mut table_rows: Vec<Vec<String>> = Vec::new();

    if let Ok(batches) = engine.query(&sql_input).await {
        extract_grid(&batches, &mut headers, &mut table_rows);
    }

    loop {
        terminal.draw(|f| {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Length(3), Constraint::Min(10), Constraint::Length(3)])
                .split(f.area());

            let query_box = Paragraph::new(sql_input.as_str())
                .style(Style::default().fg(Color::LightGreen))
                .block(Block::default().borders(Borders::ALL).title(" SQL Query (Enter=Execute, Esc=Quit) "));
            f.render_widget(query_box, chunks[0]);

            let header_cells = headers.iter().map(|h| Cell::from(h.as_str()).style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)));
            let header = Row::new(header_cells).height(1).bottom_margin(1);
            let rows = table_rows.iter().map(|r| Row::new(r.iter().map(|c| Cell::from(c.as_str()))).height(1));
            let widths: Vec<Constraint> = (0..headers.len().max(1)).map(|_| Constraint::Percentage((100 / headers.len().max(1)) as u16)).collect();

            let table = Table::new(rows, widths).header(header).block(Block::default().borders(Borders::ALL).title(" Results "));
            f.render_widget(table, chunks[1]);

            let status_bar = Paragraph::new(status_msg.as_str())
                .style(Style::default().fg(Color::Yellow))
                .block(Block::default().borders(Borders::ALL).title(" Status "));
            f.render_widget(status_bar, chunks[2]);
        })?;

        if let Event::Key(key) = event::read()? {
            if key.kind == KeyEventKind::Press {
                match key.code {
                    KeyCode::Esc => break,
                    KeyCode::Enter => match engine.query(&sql_input).await {
                        Ok(batches) => {
                            extract_grid(&batches, &mut headers, &mut table_rows);
                            status_msg = format!("Returned {} rows", table_rows.len());
                        }
                        Err(e) => { status_msg = format!("SQL Error: {}", e); }
                    },
                    KeyCode::Backspace => { sql_input.pop(); }
                    KeyCode::Char(c) => { sql_input.push(c); }
                    _ => {}
                }
            }
        }
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    Ok(())
}

fn extract_grid(batches: &[arrow::record_batch::RecordBatch], headers: &mut Vec<String>, rows: &mut Vec<Vec<String>>) {
    headers.clear();
    rows.clear();
    if let Some(first) = batches.first() {
        *headers = first.schema().fields().iter().map(|f| f.name().clone()).collect();
        for batch in batches {
            for r in 0..batch.num_rows() {
                let mut row_vec = Vec::new();
                for c in 0..batch.num_columns() {
                    let val = array_value_to_string(batch.column(c), r).unwrap_or_default();
                    row_vec.push(val);
                }
                rows.push(row_vec);
            }
        }
    }
}
