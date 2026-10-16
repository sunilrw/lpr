use crate::sym::*;
use anyhow::Result;
use arrow::csv::WriterBuilder as CsvWriterBuilder;
use arrow::json::{ArrayWriter, LineDelimitedWriter};
use arrow::record_batch::RecordBatch;
use arrow::util::pretty::pretty_format_batches;
use clap::ValueEnum;
use parquet::arrow::ArrowWriter;
use std::fs::File;
use std::io::{self, Write};

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum OutputFormat {
    #[value(alias = "datagrid", alias = "nat", alias = "grid")]
    Table,
    #[value(alias = "powershell", alias = "ps", alias = "dotnet", alias = "csharp")]
    Json,
    #[value(alias = "jsonl")]
    Ndjson,
    Csv,
    #[value(alias = "tab")]
    Tsv,
    #[value(alias = "md")]
    Markdown,
    Parquet,
    Sql,
    Xml,
    #[value(alias = "bar", alias = "histogram", alias = "goaccess")]
    Chart,
    #[value(alias = "record", alias = "card", alias = "list", alias = "gx")]
    Vertical,
}

pub fn infer_output_format_from_path(path: &str, current: OutputFormat) -> OutputFormat {
    if current != OutputFormat::Table {
        return current;
    }
    let lower = path.to_lowercase();
    if lower.ends_with(".csv") {
        OutputFormat::Csv
    } else if lower.ends_with(".tsv") {
        OutputFormat::Tsv
    } else if lower.ends_with(".json") {
        OutputFormat::Json
    } else if lower.ends_with(".ndjson") || lower.ends_with(".jsonl") {
        OutputFormat::Ndjson
    } else if lower.ends_with(".xml") {
        OutputFormat::Xml
    } else if lower.ends_with(".sql") {
        OutputFormat::Sql
    } else if lower.ends_with(".md") {
        OutputFormat::Markdown
    } else if lower.ends_with(".parquet") {
        OutputFormat::Parquet
    } else {
        current
    }
}

pub fn write_batches(
    batches: &[RecordBatch],
    format: OutputFormat,
    output_path: Option<&str>,
) -> Result<()> {
    write_batches_with_options(batches, format, output_path, Some(80))
}

pub fn write_batches_with_options(
    batches: &[RecordBatch],
    format: OutputFormat,
    output_path: Option<&str>,
    max_col_width: Option<usize>,
) -> Result<()> {
    if batches.is_empty() {
        return Ok(());
    }
    let effective_format = match output_path {
        Some(p) => infer_output_format_from_path(p, format),
        None => format,
    };

    if effective_format == OutputFormat::Parquet {
        let path = output_path.unwrap_or("output.parquet");
        let file = File::create(path)?;
        let mut writer = ArrowWriter::try_new(file, batches[0].schema(), None)?;
        for batch in batches {
            writer.write(batch)?;
        }
        writer.close()?;
        return Ok(());
    }

    let mut out: Box<dyn Write> = match output_path {
        Some(p) => Box::new(File::create(p)?),
        None => Box::new(io::stdout()),
    };

    match effective_format {
        OutputFormat::Table => {
            if let Some(max_w) = max_col_width.filter(|&w| w > 0) {
                render_bounded_ascii_table(&mut *out, batches, max_w)?;
            } else {
                let formatted = pretty_format_batches(batches)?;
                writeln!(out, "{}", formatted)?;
            }
        }
        OutputFormat::Vertical => {
            let schema = batches[0].schema();
            let headers: Vec<&str> = schema.fields().iter().map(|f| f.name().as_str()).collect();
            let max_h_len = headers.iter().map(|h| h.len()).max().unwrap_or(10);
            let mut rec_num = 0usize;
            for batch in batches {
                for r in 0..batch.num_rows() {
                    rec_num += 1;
                    writeln!(
                        out,
                        "***************************[ Record {} ]***************************",
                        rec_num
                    )?;
                    for (c, &h) in headers.iter().enumerate() {
                        let val = arrow::util::display::array_value_to_string(batch.column(c), r)
                            .unwrap_or_default();
                        writeln!(out, "  {:width$} : {}", h, val, width = max_h_len)?;
                    }
                }
            }
        }
        OutputFormat::Json => {
            let mut buf = Vec::new();
            {
                let mut writer = ArrayWriter::new(&mut buf);
                let refs: Vec<&RecordBatch> = batches.iter().collect();
                writer.write_batches(&refs)?;
                writer.finish()?;
            }
            out.write_all(&buf)?;
            writeln!(out)?;
        }
        OutputFormat::Ndjson => {
            let mut buf = Vec::new();
            {
                let mut writer = LineDelimitedWriter::new(&mut buf);
                let refs: Vec<&RecordBatch> = batches.iter().collect();
                writer.write_batches(&refs)?;
                writer.finish()?;
            }
            out.write_all(&buf)?;
        }
        OutputFormat::Csv => {
            let mut writer = CsvWriterBuilder::new().with_header(true).build(out);
            for batch in batches {
                writer.write(batch)?;
            }
        }
        OutputFormat::Tsv => {
            let mut writer = CsvWriterBuilder::new()
                .with_header(true)
                .with_delimiter(b'\t')
                .build(out);
            for batch in batches {
                writer.write(batch)?;
            }
        }
        OutputFormat::Markdown => {
            let schema = batches[0].schema();
            let headers: Vec<&str> = schema.fields().iter().map(|f| f.name().as_str()).collect();
            writeln!(out, "| {} |", headers.join(" | "))?;
            let sep: Vec<&str> = headers.iter().map(|_| "---").collect();
            writeln!(out, "| {} |", sep.join(" | "))?;
            for batch in batches {
                for row_idx in 0..batch.num_rows() {
                    let mut cells = Vec::new();
                    for col_idx in 0..batch.num_columns() {
                        let col = batch.column(col_idx);
                        let val = arrow::util::display::array_value_to_string(col, row_idx)
                            .unwrap_or_default();
                        cells.push(val);
                    }
                    writeln!(out, "| {} |", cells.join(" | "))?;
                }
            }
        }
        OutputFormat::Sql => {
            let schema = batches[0].schema();
            let cols: Vec<String> = schema
                .fields()
                .iter()
                .map(|f| format!("\"{}\"", f.name()))
                .collect();
            let col_defs: Vec<String> = schema
                .fields()
                .iter()
                .map(|f| format!("    \"{}\" TEXT", f.name()))
                .collect();
            writeln!(
                out,
                "CREATE TABLE IF NOT EXISTS lpr_export (\n{}\n);",
                col_defs.join(",\n")
            )?;
            for batch in batches {
                for row_idx in 0..batch.num_rows() {
                    let mut vals = Vec::new();
                    for col_idx in 0..batch.num_columns() {
                        let col = batch.column(col_idx);
                        if col.is_null(row_idx) {
                            vals.push("NULL".to_string());
                        } else {
                            let val = arrow::util::display::array_value_to_string(col, row_idx)
                                .unwrap_or_default()
                                .replace('\'', "''");
                            vals.push(format!("'{}'", val));
                        }
                    }
                    writeln!(
                        out,
                        "INSERT INTO lpr_export ({}) VALUES ({});",
                        cols.join(", "),
                        vals.join(", ")
                    )?;
                }
            }
        }
        OutputFormat::Xml => {
            let schema = batches[0].schema();
            let headers: Vec<&str> = schema.fields().iter().map(|f| f.name().as_str()).collect();
            writeln!(out, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>")?;
            writeln!(out, "<ROOT>")?;
            for batch in batches {
                for row_idx in 0..batch.num_rows() {
                    writeln!(out, "  <ROW>")?;
                    for (col_idx, &h) in headers.iter().enumerate() {
                        let col = batch.column(col_idx);
                        let val = arrow::util::display::array_value_to_string(col, row_idx)
                            .unwrap_or_default()
                            .replace('&', "&amp;")
                            .replace('<', "&lt;")
                            .replace('>', "&gt;");
                        writeln!(out, "    <{}>{}</{}>", h, val, h)?;
                    }
                    writeln!(out, "  </ROW>")?;
                }
            }
            writeln!(out, "</ROOT>")?;
        }
        OutputFormat::Chart => {
            // GoAccess / Log Parser CHART terminal bar chart visualization
            let schema = batches[0].schema();
            let col_count = schema.fields().len();
            let mut items: Vec<(String, f64)> = Vec::new();
            for batch in batches {
                for r in 0..batch.num_rows() {
                    let label = arrow::util::display::array_value_to_string(batch.column(0), r)
                        .unwrap_or_default();
                    let metric_col = if col_count > 1 { col_count - 1 } else { 0 };
                    let num_str =
                        arrow::util::display::array_value_to_string(batch.column(metric_col), r)
                            .unwrap_or_default();
                    let val = num_str.parse::<f64>().unwrap_or(1.0);
                    items.push((label, val));
                }
            }
            let max_val = items
                .iter()
                .map(|(_, v)| *v)
                .fold(0.0_f64, |a, b| a.max(b))
                .max(1.0);
            let label_header = schema.field(0).name();
            let metric_header = schema.field((col_count - 1).max(0)).name();
            writeln!(
                out,
                "{SYM_CHART} LPR TERMINAL BAR CHART  [{} vs {}]",
                label_header, metric_header
            )?;
            writeln!(
                out,
                "--------------------------------------------------------------------------------"
            )?;
            for (lbl, val) in items {
                let bar_len = ((val / max_val) * 40.0).round() as usize;
                let bar = "█".repeat(bar_len.max(1));
                writeln!(out, "  {:28} | {:40} ({})", truncate_str(&lbl, 28), bar, val)?;
            }
        }
        OutputFormat::Parquet => unreachable!(),
    }
    Ok(())
}

fn render_bounded_ascii_table(
    out: &mut dyn Write,
    batches: &[RecordBatch],
    max_col_width: usize,
) -> Result<()> {
    let schema = batches[0].schema();
    let headers: Vec<String> = schema.fields().iter().map(|f| f.name().clone()).collect();
    let num_cols = headers.len();
    let mut widths: Vec<usize> = headers.iter().map(|h| h.len()).collect();
    let mut grid: Vec<Vec<String>> = Vec::new();

    for batch in batches {
        for r in 0..batch.num_rows() {
            let mut row_cells = Vec::with_capacity(num_cols);
            for c in 0..num_cols {
                let raw = arrow::util::display::array_value_to_string(batch.column(c), r)
                    .unwrap_or_default();
                let clean = truncate_str(&raw, max_col_width);
                if clean.chars().count() > widths[c] {
                    widths[c] = clean.chars().count();
                }
                row_cells.push(clean);
            }
            grid.push(row_cells);
        }
    }

    let border: String = widths
        .iter()
        .map(|&w| format!("+{}", "-".repeat(w + 2)))
        .collect::<Vec<_>>()
        .join("")
        + "+";

    writeln!(out, "{}", border)?;
    let header_line: String = headers
        .iter()
        .enumerate()
        .map(|(i, h)| format!("| {:width$} ", h, width = widths[i]))
        .collect::<Vec<_>>()
        .join("")
        + "|";
    writeln!(out, "{}", header_line)?;
    writeln!(out, "{}", border)?;

    for row in grid {
        let line: String = row
            .iter()
            .enumerate()
            .map(|(i, val)| format!("| {:width$} ", val, width = widths[i]))
            .collect::<Vec<_>>()
            .join("")
            + "|";
        writeln!(out, "{}", line)?;
    }
    writeln!(out, "{}", border)?;
    Ok(())
}

fn truncate_str(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        s.to_string()
    } else {
        let mut t: String = s.chars().take(max_chars.saturating_sub(1)).collect();
        t.push('…');
        t
    }
}

pub fn batches_to_json_value(batches: &[RecordBatch]) -> Result<serde_json::Value> {
    if batches.is_empty() {
        return Ok(serde_json::json!([]));
    }
    let mut buf = Vec::new();
    {
        let mut writer = ArrayWriter::new(&mut buf);
        let refs: Vec<&RecordBatch> = batches.iter().collect();
        writer.write_batches(&refs)?;
        writer.finish()?;
    }
    let val: serde_json::Value = serde_json::from_slice(&buf)?;
    Ok(val)
}
