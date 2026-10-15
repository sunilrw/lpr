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
    Table, Json, Ndjson, Csv, Markdown, Parquet, Sql,
}

pub fn write_batches(batches: &[RecordBatch], format: OutputFormat, output_path: Option<&str>) -> Result<()> {
    if batches.is_empty() { return Ok(()); }
    if format == OutputFormat::Parquet {
        let path = output_path.unwrap_or("output.parquet");
        let file = File::create(path)?;
        let mut writer = ArrowWriter::try_new(file, batches[0].schema(), None)?;
        for batch in batches { writer.write(batch)?; }
        writer.close()?;
        return Ok(());
    }

    let mut out: Box<dyn Write> = match output_path {
        Some(p) => Box::new(File::create(p)?),
        None => Box::new(io::stdout()),
    };

    match format {
        OutputFormat::Table => {
            let formatted = pretty_format_batches(batches)?;
            writeln!(out, "{}", formatted)?;
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
            for batch in batches { writer.write(batch)?; }
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
                        let val = arrow::util::display::array_value_to_string(col, row_idx).unwrap_or_default();
                        cells.push(val);
                    }
                    writeln!(out, "| {} |", cells.join(" | "))?;
                }
            }
        }
        OutputFormat::Sql => {
            let schema = batches[0].schema();
            let cols: Vec<String> = schema.fields().iter().map(|f| format!("\"{}\"", f.name())).collect();
            let col_defs: Vec<String> = schema.fields().iter().map(|f| format!("    \"{}\" TEXT", f.name())).collect();
            writeln!(out, "CREATE TABLE IF NOT EXISTS lpr_export (\n{}\n);", col_defs.join(",\n"))?;
            for batch in batches {
                for row_idx in 0..batch.num_rows() {
                    let mut vals = Vec::new();
                    for col_idx in 0..batch.num_columns() {
                        let col = batch.column(col_idx);
                        if col.is_null(row_idx) { vals.push("NULL".to_string()); }
                        else {
                            let val = arrow::util::display::array_value_to_string(col, row_idx).unwrap_or_default().replace('\'', "''");
                            vals.push(format!("'{}'", val));
                        }
                    }
                    writeln!(out, "INSERT INTO lpr_export ({}) VALUES ({});", cols.join(", "), vals.join(", "))?;
                }
            }
        }
        OutputFormat::Parquet => unreachable!(),
    }
    Ok(())
}

pub fn batches_to_json_value(batches: &[RecordBatch]) -> Result<serde_json::Value> {
    if batches.is_empty() { return Ok(serde_json::json!([])); }
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
