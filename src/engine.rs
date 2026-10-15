use crate::checkpoint::CheckpointStore;
use crate::parsers::{
    detect_format, parse_aws_alb_files, parse_aws_s3_files, parse_aws_vpc_files,
    parse_azure_blob_files, parse_cef_files, parse_cisco_asa_files, parse_cisco_config_files,
    parse_evtx_files, parse_excel_files, parse_firewall_kv_files, parse_ias_files,
    parse_json_files, parse_nginx_files, parse_raw_lines_with_checkpoint, parse_regex_files,
    parse_syslog_files, parse_w3c_files, resolve_paths, InputFormat,
};
use crate::udfs::register_all_udfs;
use anyhow::Result;
use arrow::record_batch::RecordBatch;
use datafusion::datasource::MemTable;
use datafusion::prelude::*;
use regex::Regex;
use std::sync::Arc;

pub struct LogEngine {
    pub ctx: SessionContext,
}

impl LogEngine {
    pub fn new() -> Self {
        let config = SessionConfig::new().with_target_partitions(num_cpus());
        let ctx = SessionContext::new_with_config(config);
        register_all_udfs(&ctx);
        Self { ctx }
    }

    pub async fn register_source(&self, table_name: &str, path_pattern: &str, format: InputFormat, custom_regex: Option<&str>) -> Result<InputFormat> {
        self.register_source_with_checkpoint(table_name, path_pattern, format, custom_regex, None).await
    }

    pub async fn register_source_with_checkpoint(&self, table_name: &str, path_pattern: &str, format: InputFormat, custom_regex: Option<&str>, ckpt: Option<&mut CheckpointStore>) -> Result<InputFormat> {
        let paths = resolve_paths(path_pattern)?;
        let effective_format = if format == InputFormat::Auto { detect_format(&paths[0]) } else { format };

        match effective_format {
            InputFormat::Csv => { self.ctx.register_csv(table_name, path_pattern, CsvReadOptions::new()).await?; }
            InputFormat::Tsv => { self.ctx.register_csv(table_name, path_pattern, CsvReadOptions::new().delimiter(b'\t')).await?; }
            InputFormat::Excel => { let b = parse_excel_files(&paths)?; self.register_batch(table_name, b)?; }
            InputFormat::Parquet => { self.ctx.register_parquet(table_name, path_pattern, ParquetReadOptions::default()).await?; }
            InputFormat::W3c => { let b = parse_w3c_files(&paths)?; self.register_batch(table_name, b)?; }
            InputFormat::Json | InputFormat::Akamai | InputFormat::Gcp => { let b = parse_json_files(&paths)?; self.register_batch(table_name, b)?; }
            InputFormat::Nginx => { let b = parse_nginx_files(&paths)?; self.register_batch(table_name, b)?; }
            InputFormat::Syslog => { let b = parse_syslog_files(&paths)?; self.register_batch(table_name, b)?; }
            InputFormat::Evtx => { let b = parse_evtx_files(&paths)?; self.register_batch(table_name, b)?; }
            InputFormat::FirewallKv => { let b = parse_firewall_kv_files(&paths)?; self.register_batch(table_name, b)?; }
            InputFormat::CiscoAsa => { let b = parse_cisco_asa_files(&paths)?; self.register_batch(table_name, b)?; }
            InputFormat::CiscoConfig => { let b = parse_cisco_config_files(&paths)?; self.register_batch(table_name, b)?; }
            InputFormat::Cef => { let b = parse_cef_files(&paths)?; self.register_batch(table_name, b)?; }
            InputFormat::Ias => { let b = parse_ias_files(&paths)?; self.register_batch(table_name, b)?; }
            InputFormat::AwsS3 => { let b = parse_aws_s3_files(&paths)?; self.register_batch(table_name, b)?; }
            InputFormat::AwsVpc => { let b = parse_aws_vpc_files(&paths)?; self.register_batch(table_name, b)?; }
            InputFormat::AwsAlb => { let b = parse_aws_alb_files(&paths)?; self.register_batch(table_name, b)?; }
            InputFormat::AzureBlob => { let b = parse_azure_blob_files(&paths)?; self.register_batch(table_name, b)?; }
            InputFormat::Regex => {
                let pattern = custom_regex.ok_or_else(|| anyhow::anyhow!("--regex-pattern required for -i regex"))?;
                let re = Regex::new(pattern)?;
                let b = parse_regex_files(&paths, &re)?;
                self.register_batch(table_name, b)?;
            }
            InputFormat::Line | InputFormat::Auto => {
                let b = parse_raw_lines_with_checkpoint(&paths, ckpt)?;
                self.register_batch(table_name, b)?;
            }
        }
        Ok(effective_format)
    }

    fn register_batch(&self, table_name: &str, batch: RecordBatch) -> Result<()> {
        let schema = batch.schema();
        let mem_table = MemTable::try_new(schema, vec![vec![batch]])?;
        self.ctx.register_table(table_name, Arc::new(mem_table))?;
        Ok(())
    }

    pub async fn query(&self, sql: &str) -> Result<Vec<RecordBatch>> {
        let df = self.ctx.sql(sql).await?;
        let batches = df.collect().await?;
        Ok(batches)
    }
}

fn num_cpus() -> usize {
    std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4)
}
