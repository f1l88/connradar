use std::collections::HashSet;
use std::process::Command;
use std::thread;
use std::time::{Duration, SystemTime};
use chrono::{DateTime, Local};
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{Write, BufRead, BufReader};
use std::sync::{Arc, Mutex};
use std::net::IpAddr;
use config::{Config, ConfigError, File as ConfigFile};
use std::env;
use dns_lookup::lookup_addr;
use ipnet::IpNet;
//use tracing::{info, warn, error};

#[cfg(test)]
mod tests;

// Структура для конфигурации
#[derive(Debug, Serialize, Deserialize, Clone)]
struct AppConfig {
    monitor: MonitorConfig,
    filtering: FilteringConfig,
    files: FileConfig,
    alerts: AlertConfig,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
enum TrafficType {
    Outgoing,   // Только исходящие соединения
    Incoming,   // Только входящие соединения  
    All,        // Все соединения (по умолчанию)
}

impl Default for TrafficType {
    fn default() -> Self {
        Self::All
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct MonitorConfig {
    alert_interval_minutes: u64,
    check_interval_seconds: u64,
    max_history_age_days: u32,
    export_report_interval: u64,
    traffic_type: TrafficType, // type of traffic
    debug: bool,
    pub resolve_dns: bool,           // enable DNS-resolve
    pub dns_timeout_ms: u64,         // timeout
    pub resolve_only_private: bool,
    pub group_by_ip: bool,  // true – группировать по IP, false – отслеживать IP:port
    pub show_ports_in_logs: bool,
    pub include_ports_in_history: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct FilteringConfig {
    ignore_ips: Vec<String>,
    ignore_private_ips: bool,
    ignore_public_ips: bool,
    ignore_localhost: bool,
    ignore_ports: Vec<u16>,
    #[serde(deserialize_with = "deserialize_empty_vec_as_none")]
    pub monitor_only_ports: Option<Vec<u16>>,
    pub allowed_subnets: Option<Vec<String>>,
    ignore_ipv6: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct FileConfig {
    data_file: String,
    log_file: String,
    config_file: String,
    report_file: String,
    max_log_size_mb: u64,
    max_log_files: usize,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct AlertConfig {
    enable_console_alerts: bool,
    enable_log_alerts: bool,
    alert_on_new_connection: bool,
    alert_on_disconnection: bool,
    alert_threshold_count: Option<u32>,
}

impl AppConfig {
    fn new() -> Result<Self, ConfigError> {
        let default_config_path = "config.toml";
        
        let settings = Config::builder()
            // Добавляем значения по умолчанию
            .set_default("monitor.alert_interval_minutes", 5)?
            .set_default("monitor.check_interval_seconds", 10)?
            .set_default("monitor.max_history_age_days", 30)?
            .set_default("monitor.export_report_interval", 300)?
            .set_default("monitor.traffic_type", "all")?
            .set_default("monitor.debug", false)?
            .set_default("monitor.resolve_dns", false)?
            .set_default("monitor.dns_timeout_ms", 2000)?
            .set_default("monitor.resolve_only_private", true)?
            .set_default("monitor.group_by_ip", true)?
            .set_default("monitor.show_ports_in_logs", true)?
            .set_default("monitor.include_ports_in_history", true)?

            .set_default("filtering.ignore_private_ips", true)?
            .set_default("filtering.ignore_public_ips", false)?
            .set_default("filtering.ignore_localhost", true)?
            .set_default("filtering.ignore_ipv6", true)?
            .set_default("filtering.ignore_ips", Vec::<String>::new())?
            .set_default("filtering.ignore_ports", Vec::<u16>::new())?
            .set_default("filtering.allowed_subnets", Option::<Vec<String>>::None)?
            .set_default("filtering.monitor_only_ports", Option::<Vec<u16>>::None)?
            
            .set_default("files.data_file", "connections.jsonl")?
            .set_default("files.log_file", "connection_monitor.log")?
            .set_default("files.config_file", "config.toml")?
            .set_default("files.report_file", "connection_report.txt")?
            .set_default("files.max_log_size_mb", 10)?
            .set_default("files.max_log_files", 5)?
            
            .set_default("alerts.enable_console_alerts", true)?
            .set_default("alerts.enable_log_alerts", true)?
            .set_default("alerts.alert_on_new_connection", false)?
            .set_default("alerts.alert_on_disconnection", true)?
            .set_default("alerts.alert_threshold_count", Option::<u32>::None)?
            
            .add_source(ConfigFile::with_name(default_config_path).required(false))
            .build()?;
        
        settings.try_deserialize()
    }
    
    fn load_from_file(path: &str) -> Result<Self, ConfigError> {
        let settings = Config::builder()
            .add_source(ConfigFile::with_name(path))
            .build()?;
        
        settings.try_deserialize()
    }
    
    fn save_to_file(&self, path: &str) -> Result<(), std::io::Error> {
        let toml = toml::to_string_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        
        std::fs::write(path, toml)?;
        Ok(())
    }
    
    fn create_default_config(&self) -> Result<(), std::io::Error> {
        let config_path = &self.files.config_file;
        if !std::path::Path::new(config_path).exists() {
            println!("Creating default configuration file: {}", config_path);
            self.save_to_file(config_path)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq)]
enum ConnectionDirection {
    Incoming,
    Outgoing,
    Unknown,
}

// Структура для хранения информации о соединении
#[derive(Debug)]
struct ParsedConnection {
    remote_ip: String,
    remote_port: String,
    local_ip: String,
    local_port: String,
    protocol: String,
    direction: ConnectionDirection,
    state: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Connection {
    pub ip_address: String,
    pub hostname: Option<String>, 
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ports: Option<Vec<PortInfo>>,
    pub discovered_at: String,
    pub last_seen: String,
    pub protocol: String,
    pub direction: String,
    pub local_port: String,
    pub local_ip: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct PortInfo {
    pub port: String,
    pub state: String,
}

// Структура для логирования
#[derive(Debug)]
struct Logger {
    log_file: String,
    enable_logging: bool,
    max_size_mb: u64,
    max_files: usize,
}

fn deserialize_empty_vec_as_none<'de, D>(deserializer: D) -> Result<Option<Vec<u16>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let opt = Option::<Vec<u16>>::deserialize(deserializer)?;
    match opt {
        Some(v) if v.is_empty() => Ok(None),
        other => Ok(other),
    }
}

impl Logger {
    fn new(config: &FileConfig) -> Self {
        Self {
            log_file: config.log_file.clone(),
            enable_logging: true,
            max_size_mb: config.max_log_size_mb,
            max_files: config.max_log_files,
        }
    }
    
    fn log(&self, level: &str, message: &str) -> std::io::Result<()> {
        if !self.enable_logging {
            return Ok(());
        }
        
        self.check_rotation()?;
        
        let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S%.3f");
        let log_message = format!("[{}] [{}] {}\n", timestamp, level, message);
        
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_file)?;
        
        file.write_all(log_message.as_bytes())?;
        Ok(())
    }
    
    fn info(&self, message: &str) -> std::io::Result<()> {
        println!("[INFO] {}", message);
        self.log("INFO", message)
    }
    
    fn warn(&self, message: &str) -> std::io::Result<()> {
        println!("[WARN] {}", message);
        self.log("WARN", message)
    }
    
    fn error(&self, message: &str) -> std::io::Result<()> {
        eprintln!("[ERROR] {}", message);
        self.log("ERROR", message)
    }
    
    fn alert(&self, message: &str) -> std::io::Result<()> {
        println!("[ALERT] {}", message);
        self.log("ALERT", message)
    }
    
    fn check_rotation(&self) -> std::io::Result<()> {
        let max_size = self.max_size_mb * 1024 * 1024;
        
        if let Ok(metadata) = std::fs::metadata(&self.log_file) {
            if metadata.len() > max_size {
                self.rotate_logs()?;
            }
        }
        Ok(())
    }
    
    fn rotate_logs(&self) -> std::io::Result<()> {
        // Удаляем самый старый лог
        let oldest_log = format!("{}.{}", self.log_file, self.max_files);
        if std::fs::exists(&oldest_log)? {
            std::fs::remove_file(&oldest_log)?;
        }
        
        // Сдвигаем все логи
        for i in (1..self.max_files).rev() {
            let old_name = format!("{}.{}", self.log_file, i);
            let new_name = format!("{}.{}", self.log_file, i + 1);
            
            if std::fs::exists(&old_name)? {
                std::fs::rename(&old_name, &new_name)?;
            }
        }
        
        // Переименовываем текущий лог
        let first_backup = format!("{}.1", self.log_file);
        if std::fs::exists(&self.log_file)? {
            std::fs::rename(&self.log_file, &first_backup)?;
        }
        
        Ok(())
    }
    
    fn debug(&self, message: &str) -> std::io::Result<()> {
        // Пишем только в файл, в консоль ничего не выводим
        if !self.enable_logging {
            return Ok(());
        }
        self.check_rotation()?;
        let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S%.3f");
        let log_message = format!("[{}] [DEBUG] {}\n", timestamp, message);
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_file)?;
        file.write_all(log_message.as_bytes())?;
        Ok(())
    }
}

/// Проверяет, входит ли IP-адрес хотя бы в одну из указанных подсетей (CIDR).
fn ip_in_any_subnet(ip: &str, subnets: &[String]) -> bool {
    let ip = match ip.parse::<std::net::IpAddr>() {
        Ok(ip) => ip,
        Err(_) => return false,
    };
    for subnet_str in subnets {
        if let Ok(subnet) = subnet_str.parse::<IpNet>() {
            if subnet.contains(&ip) {
                return true;
            }
        }
    }
    false
}

#[derive(Debug)]
struct ConnectionMonitor {
    current_connections: HashSet<String>,
    history: Vec<Connection>,
    config: AppConfig,
    logger: Logger,
}

impl ConnectionMonitor {
    fn new(config: AppConfig) -> Self {
        let logger = Logger::new(&config.files);
        
        let monitor = Self {
            current_connections: HashSet::new(),
            history: Vec::new(),
            config,
            logger,
        };
        
        monitor.initialize_files().unwrap_or_else(|e| {
            eprintln!("Warning: Failed to initialize files: {}", e);
        });
        
        monitor
    }
    
    fn initialize_files(&self) -> std::io::Result<()> {
        if let Some(parent) = std::path::Path::new(&self.config.files.data_file).parent() {
            if !parent.exists() {
                std::fs::create_dir_all(parent)?;
            }
        }
        
        if !std::path::Path::new(&self.config.files.data_file).exists() {
            File::create(&self.config.files.data_file)?;
            let _ = self.logger.info(&format!(
                "Created new data file: {}", 
                self.config.files.data_file
            ));
        }
        
        if let Some(parent) = std::path::Path::new(&self.config.files.log_file).parent() {
            if !parent.exists() {
                std::fs::create_dir_all(parent)?;
            }
        }
        
        Ok(())
    }

    fn load_history(&mut self) -> std::io::Result<()> {
        let data_file_path = &self.config.files.data_file;
        
        match std::fs::metadata(data_file_path) {
            Ok(metadata) => {
                if metadata.len() == 0 {
                    let _ = self.logger.info("Data file is empty, starting with fresh history");
                    return Ok(());
                }
                
                let file = File::open(data_file_path)?;
                let reader = BufReader::new(file);
                let mut count = 0;
                let mut error_count = 0;
                
                for (line_num, line) in reader.lines().enumerate() {
                    match line {
                        Ok(line) => {
                            let trimmed = line.trim();
                            if trimmed.is_empty() {
                                continue;
                            }
                            
                            match serde_json::from_str::<Connection>(trimmed) {
                                Ok(conn) => {
                                    self.history.push(conn);
                                    count += 1;
                                }
                                Err(e) => {
                                    error_count += 1;
                                    if error_count <= 5 {
                                        let _ = self.logger.warn(&format!(
                                            "Failed to parse line {} in data file: {}",
                                            line_num + 1, e
                                        ));
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            error_count += 1;
                            let _ = self.logger.warn(&format!(
                                "Failed to read line from data file: {}",
                                e
                            ));
                        }
                    }
                }
                
                if error_count > 5 {
                    let _ = self.logger.warn(&format!(
                        "Total parsing errors in data file: {}",
                        error_count
                    ));
                }
                
                let _ = self.logger.info(&format!(
                    "Successfully loaded {} connections from history", 
                    count
                ));
            }
            Err(e) => {
                let _ = self.logger.warn(&format!(
                    "Could not access data file {}: {}. Starting fresh.",
                    data_file_path, e
                ));
            }
        }
        
        Ok(())
    }

    fn save_all_history(&self) -> std::io::Result<()> {
        let mut file = File::create(&self.config.files.data_file)?;
        for conn in &self.history {
            let mut export_conn = conn.clone();
            if !self.config.monitor.include_ports_in_history {
                export_conn.ports = vec![].into();
            }
            let json = serde_json::to_string(&export_conn)?;
            writeln!(file, "{}", json)?;
        }
        Ok(())
    }

    fn is_ip_ignored(&self, ip: &str) -> bool {
        //println!("DEBUG: Checking if IP {} is ignored", ip);

        if self.config.filtering.ignore_ips.contains(&ip.to_string()) {
            return true;
        }
        
        if self.config.filtering.ignore_localhost && 
           (ip == "127.0.0.1" || ip == "localhost" || ip == "::1") {
            return true;
        }
        
        if self.config.filtering.ignore_private_ips {
            if ip.starts_with("10.") ||
               ip.starts_with("192.168.") ||
               (ip.starts_with("172.") && {
                   if let Some(second) = ip.split('.').nth(1) {
                       if let Ok(num) = second.parse::<u8>() {
                           num >= 16 && num <= 31
                       } else {
                           false
                       }
                   } else {
                       false
                   }
               }) {
                return true;
            }
        }

        // Ignore publiic ips address
        if self.config.filtering.ignore_public_ips && !Self::is_private_ip(ip) {
            return true;
        }

        // Проверка allowed_subnets (белый список)
        if let Some(ref subnets) = self.config.filtering.allowed_subnets {
            if !subnets.is_empty() && !ip_in_any_subnet(ip, subnets) {
                return true;
            }
        }
        
        false
    }

    fn get_current_connections(&self) -> Result<Vec<ParsedConnection>, Box<dyn std::error::Error>> {
        if cfg!(target_os = "windows") {
            self.get_current_connections_windows()
        } else {
            self.get_current_connections_linux()
        }
    }

    fn get_current_connections_linux(&self) -> Result<Vec<ParsedConnection>, Box<dyn std::error::Error>> {
        let ip_flags = if self.config.filtering.ignore_ipv6 {
            vec!["-4"]
        } else {
            vec!["-4", "-6"]
        };
        
        let output = Command::new("ss")
            .args(["-tun"])
            .args(&ip_flags)
            .output()?;
        
        if !output.status.success() {
            let error_msg = String::from_utf8_lossy(&output.stderr);
            return Err(format!("ss command failed: {}", error_msg).into());
        }
        
        let output_str = String::from_utf8(output.stdout)?;
        let mut connections = Vec::new();

        // Логирование первых 5 строк сырого вывода (отладка)
        let _ = self.logger.info(&format!(
            "Raw ss output ({} lines):",
            output_str.lines().count()
        ));
        for line in output_str.lines().take(5) {
            let _ = self.logger.info(&format!("  {}", line));
        }

        for line in output_str.lines().skip(1) {
            if let Some(conn) = self.parse_ss_line(line) {
                // Применяем фильтр по типу трафика
                match self.config.monitor.traffic_type {
                    TrafficType::Outgoing if conn.direction == ConnectionDirection::Incoming => continue,
                    TrafficType::Incoming if conn.direction == ConnectionDirection::Outgoing => continue,
                    _ => {}
                }
                connections.push(conn);
            }
        }
        
        Ok(connections)
    }

    fn get_current_connections_windows(&self) -> Result<Vec<ParsedConnection>, Box<dyn std::error::Error>> {
        let mut connections = Vec::new();

        // TCP соединения
        let tcp_output = Command::new("netstat")
            .args(["-anop", "TCP"])
            .output()?;
        self.parse_netstat_output(&tcp_output.stdout, "TCP", &mut connections)?;

        // UDP соединения
        let udp_output = Command::new("netstat")
            .args(["-anop", "UDP"])
            .output()?;
        self.parse_netstat_output(&udp_output.stdout, "UDP", &mut connections)?;

        Ok(connections)
    }

    fn parse_netstat_output(&self, stdout: &[u8], default_proto: &str, connections: &mut Vec<ParsedConnection>) -> Result<(), Box<dyn std::error::Error>> {
        let output_str = String::from_utf8_lossy(stdout);
        for line in output_str.lines() {
            let trimmed = line.trim();
            // Пропускаем заголовки, пустые строки, строки "Active Connections"
            if trimmed.is_empty() 
                || trimmed.starts_with("Active") 
                || trimmed.starts_with("Proto") {
                continue;
            }
            if let Some(conn) = self.parse_netstat_line(trimmed, default_proto) {
                // Применяем фильтр traffic_type
                match self.config.monitor.traffic_type {
                    TrafficType::Outgoing if conn.direction == ConnectionDirection::Incoming => continue,
                    TrafficType::Incoming if conn.direction == ConnectionDirection::Outgoing => continue,
                    _ => {}
                }
                connections.push(conn);
            }
        }
        Ok(())
    }
    
    fn parse_ss_line(&self, line: &str) -> Option<ParsedConnection> {
        let trimmed_line = line.trim();
        if trimmed_line.is_empty() {
            return None;
        }
        
        let parts: Vec<&str> = trimmed_line.split_whitespace().collect();
        
        // Отладка: вывести все части
        //println!("DEBUG parse_ss_line - Line: {}", line);
        //println!("  -> Parts ({}): {:?}", parts.len(), parts);
        
        // Нужно минимум 6 частей: Netid State Recv-Q Send-Q Local:Port Peer:Port
        if parts.len() < 6 {
            println!("  -> Skipping: not enough parts");
            return None;
        }
        
        let state = parts[1].to_string(); // State находится на позиции 1
        let protocol = if line.contains("tcp") { "TCP" } else { "UDP" }.to_string();
        
        // Определяем индексы для адресов
        // Формат: Index 0: Netid (tcp/udp), 1: State, 2: Recv-Q, 3: Send-Q
        // Local Address начинается с индекса 4
        
        // Пробуем найти правильные индексы
        let mut local_idx = 4;
        let mut remote_idx = 5;
        
        // Проверим, если в строке есть дополнительные поля (например, Process)
        if parts.len() >= 7 {
            // Проверяем, похожи ли предполагаемые адреса на адреса (содержат :)
            if !parts[4].contains(':') && parts[5].contains(':') && parts[6].contains(':') {
                // parts[4] не адрес, значит есть дополнительное поле
                local_idx = 5;
                remote_idx = 6;
                println!("  -> Using indices 5,6 (with extra field)");
            } else if parts[4].contains(':') && parts[5].contains(':') {
                // Стандартный формат
                println!("  -> Using indices 4,5 (standard format)");
            }
        } else {
            println!("  -> Using indices 4,5 (minimal format)");
        }
        
        // Проверяем, что индексы в пределах массива
        if local_idx >= parts.len() || remote_idx >= parts.len() {
            println!("  -> Skipping: address indices out of bounds");
            return None;
        }
        
        let local = parts[local_idx];
        let remote = parts[remote_idx];
        
        println!("  -> Selected: local={}, remote={}", local, remote);
        
        // Парсим адреса
        let (local_ip, local_port) = match Self::parse_address(local) {
            Some((ip, port)) => (ip, port),
            None => {
                println!("  -> Skipping: cannot parse local address '{}'", local);
                return None;
            }
        };
        
        let (remote_ip, remote_port) = match Self::parse_address(remote) {
            Some((ip, port)) => (ip, port),
            None => {
                println!("  -> Skipping: cannot parse remote address '{}'", remote);
                return None;
            }
        };
        
        println!("  -> Parsed: {}:{} -> {}:{}", 
                local_ip, local_port, remote_ip, remote_port);
        
        // Пропускаем слушающие сокеты (с удаленным адресом 0.0.0.0 или *)
        if remote_ip == "0.0.0.0" || remote_ip == "*" || remote_ip == "::" {
            println!("  -> Skipping: listening socket");
            return None;
        }
        
        // Проверяем фильтры
        if self.is_ip_ignored(&remote_ip) {
            println!("  -> Skipping: remote IP {} is ignored", remote_ip);
            return None;
        }
        
        // Проверяем порты для игнорирования
        if let Ok(port_num) = remote_port.parse::<u16>() {
            if self.config.filtering.ignore_ports.contains(&port_num) {
                println!("  -> Skipping: port {} is in ignore_ports", port_num);
                return None;
            }
            
            // Check local_port and remote_port
        if let Some(ref monitor_ports) = self.config.filtering.monitor_only_ports {
            let local_ok = local_port.parse::<u16>().map(|p| monitor_ports.contains(&p)).unwrap_or(false);
            let remote_ok = remote_port.parse::<u16>().map(|p| monitor_ports.contains(&p)).unwrap_or(false);
            if !local_ok && !remote_ok {
                return None;
            }
        }
        }
        
        // Определяем направление соединения
        let direction = Self::determine_direction(&state, &local_ip, &local_port, &remote_ip);
        if self.config.monitor.debug {
            let _ = self.logger.debug(&format!(
                "Direction for {}:{} -> {}:{} = {:?}, state={}",
                local_ip, local_port, remote_ip, remote_port, direction, state
            ));
        }
        
        // Применяем фильтр по типу трафика
        match self.config.monitor.traffic_type {
            TrafficType::Outgoing if direction == ConnectionDirection::Incoming => {
                println!("  -> Skipping: traffic_type=Outgoing but direction=Incoming");
                return None;
            }
            TrafficType::Incoming if direction == ConnectionDirection::Outgoing => {
                println!("  -> Skipping: traffic_type=Incoming but direction=Outgoing");
                return None;
            }
            _ => {}
        }
        
        Some(ParsedConnection {
            remote_ip,
            remote_port,
            local_ip,
            local_port,
            protocol,
            direction,
            state,
        })
    }

    fn parse_netstat_line(&self, line: &str, default_proto: &str) -> Option<ParsedConnection> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        // netstat -anop TCP выводит: Proto LocalAddress ForeignAddress State PID
        // netstat -anop UDP выводит: Proto LocalAddress ForeignAddress PID
        // Минимум нужно 4 части для UDP: Proto, Local, Foreign, PID
        if parts.len() < 4 {
            return None;
        }

        let proto = if parts[0] == "TCP" || parts[0] == "UDP" {
            parts[0].to_string()
        } else {
            default_proto.to_string()
        };

        let local = parts[1];
        let remote = parts[2];

        // Для TCP есть State на позиции 3, PID на 4; для UDP State отсутствует
        let state = if proto == "TCP" && parts.len() >= 5 {
            parts[3].to_string()
        } else {
            // Можно проставить LISTEN или просто протокол
            proto.clone()
        };

        let (local_ip, local_port) = Self::parse_address(local)?;
        let (remote_ip, remote_port) = Self::parse_address(remote)?;

        // Пропускаем слушающие сокеты (удалённый адрес 0.0.0.0 или *)
        if remote_ip == "0.0.0.0" || remote_ip == "*" || remote_ip == "::" {
            return None;
        }

        // Проверка фильтров (как в оригинальном методе)
        if self.is_ip_ignored(&remote_ip) {
            return None;
        }
        if let Ok(port_num) = remote_port.parse::<u16>() {
            if self.config.filtering.ignore_ports.contains(&port_num) {
                return None;
            }
            if let Some(ref monitor_ports) = self.config.filtering.monitor_only_ports {
                if !monitor_ports.contains(&port_num) {
                    return None;
                }
            }
        }

        let direction = Self::determine_direction(&state, &local_ip, &local_port, &remote_ip);

        Some(ParsedConnection {
            remote_ip,
            remote_port,
            local_ip,
            local_port,
            protocol: proto,
            direction,
            state,
        })
    }
    // Также обновите метод parse_address для лучшей обработки
    fn parse_address(addr: &str) -> Option<(String, String)> {
        // Удаляем квадратные скобки у IPv6 адресов
        let addr = addr.trim();
        
        // Обработка IPv6 адресов в формате [::ffff:1.2.3.4]:port
        if addr.starts_with('[') && addr.contains(']') {
            if let Some(bracket_end) = addr.find(']') {
                let ip = &addr[1..bracket_end];
                let rest = &addr[bracket_end+1..];
                if rest.starts_with(':') {
                    let port = &rest[1..];
                    return Some((ip.to_string(), port.to_string()));
                }
            }
        }
        
        // Обычные IPv4 адреса или IPv6 без скобок
        addr.rsplit_once(':')
            .map(|(ip, port)| (ip.to_string(), port.to_string()))
    }
    
    fn determine_direction(state: &str, local_ip: &str, local_port: &str, remote_ip: &str) -> ConnectionDirection {
        // 1. По состоянию соединения (более точная проверка)
        let state_upper = state.to_uppercase();
        if state_upper.contains("SYN_SENT") || state_upper.contains("SYN-RECV") {
            println!("    -> Outgoing (SYN_SENT/SYN-RECV state)");
            return ConnectionDirection::Outgoing;
        }
        
        // 2. Если удаленный порт известный (менее 1024), вероятно входящее
        if let Ok(remote_port_num) = local_port.parse::<u16>() {
            if remote_port_num < 1024 {
                println!("    -> Incoming (local port {} < 1024)", remote_port_num);
                return ConnectionDirection::Incoming;
            }
        }
        
        // 3. По приватности IP-адресов
        let local_is_private = Self::is_private_ip(local_ip);
        let remote_is_private = Self::is_private_ip(remote_ip);
        
        println!("    -> local_is_private={}, remote_is_private={}", 
                local_is_private, remote_is_private);
        
        if !local_is_private && remote_is_private {
            // Локальный публичный, удаленный приватный = входящее
            println!("    -> Incoming (local public, remote private)");
            return ConnectionDirection::Incoming;
        }
        
        if local_is_private && !remote_is_private {
            // Локальный приватный, удаленный публичный = исходящее
            println!("    -> Outgoing (local private, remote public)");
            return ConnectionDirection::Outgoing;
        }
        
        // 4. Для локальных соединений (оба приватные)
        if local_is_private && remote_is_private {
            // Сложно определить, но можно по портам
            if let (Ok(local_port_num), Ok(remote_port_num)) = 
                (local_port.parse::<u16>(), remote_ip.split(':').last().unwrap_or("0").parse::<u16>()) {
                
                if local_port_num > 1024 && remote_port_num <= 1024 {
                    println!("    -> Outgoing (local high port to remote low port)");
                    return ConnectionDirection::Outgoing;
                } else if local_port_num <= 1024 && remote_port_num > 1024 {
                    println!("    -> Incoming (local low port to remote high port)");
                    return ConnectionDirection::Incoming;
                }
            }
        }
        
        println!("    -> Unknown direction");
        ConnectionDirection::Unknown
    }
    
    fn is_private_ip(ip: &str) -> bool {
        // Удаляем квадратные скобки для IPv6
        let ip = ip.trim_start_matches('[').trim_end_matches(']');
        
        // Проверка IPv4 приватных диапазонов
        if let Ok(ipv4) = ip.parse::<std::net::Ipv4Addr>() {
            let octets = ipv4.octets();
            
            // 10.0.0.0/8
            if octets[0] == 10 {
                return true;
            }
            
            // 172.16.0.0/12
            if octets[0] == 172 && (octets[1] >= 16 && octets[1] <= 31) {
                return true;
            }
            
            // 192.168.0.0/16
            if octets[0] == 192 && octets[1] == 168 {
                return true;
            }
            
            // 127.0.0.0/8 (localhost)
            if octets[0] == 127 {
                return true;
            }
            
            // 169.254.0.0/16 (link-local)
            if octets[0] == 169 && octets[1] == 254 {
                return true;
            }
            
            return false;
        }
        
        // Проверка IPv6 приватных адресов
        if let Ok(ipv6) = ip.parse::<std::net::Ipv6Addr>() {
            // ::1 (localhost)
            if ipv6 == std::net::Ipv6Addr::LOCALHOST {
                return true;
            }
            
            // fe80::/10 (link-local)
            let segments = ipv6.segments();
            if (segments[0] & 0xffc0) == 0xfe80 {
                return true;
            }
            
            // fc00::/7 (ULA - unique local addresses)
            if (segments[0] & 0xfe00) == 0xfc00 {
                return true;
            }
        }
        
        false
    }

    fn check_connections(&mut self) -> Result<(Vec<String>, Vec<String>), Box<dyn std::error::Error>> {
        let current = self.get_current_connections()?;

        // Ключ – только IP (группировка по хосту)
        let current_set: HashSet<String> = current.iter()
            .map(|conn| conn.remote_ip.clone())
            .collect();

        let disappeared: Vec<String> = self.current_connections
            .difference(&current_set)
            .cloned()
            .collect();

        let new_connections: Vec<String> = current_set
            .difference(&self.current_connections)
            .cloned()
            .collect();

        // Логируем новые соединения
        if self.config.alerts.alert_on_new_connection {
            for ip in &new_connections {
                if let Some(saved_conn) = self.history.iter().find(|c| &c.ip_address == ip) {
                    let hostname_str = saved_conn.hostname.as_deref().unwrap_or("N/A");
                    let ports_part = if self.config.monitor.show_ports_in_logs {
                        if let Some(ref ports) = saved_conn.ports {
                            let ports_desc: Vec<String> = ports.iter()
                                .map(|p| format!("{} ({})", p.port, p.state))
                                .collect();
                            format!(" | Ports: {}", ports_desc.join(", "))
                        } else {
                            String::new()
                        }
                    } else {
                        String::new()
                    };
                    let _ = self.logger.info(&format!(
                        "New connection(s) from {} ({}){} | Direction: {}",
                        ip, hostname_str, ports_part, saved_conn.direction
                    ));
                }
            }
        }

        self.current_connections = current_set;

        let now = Local::now().to_rfc3339();
        for conn in &current {
            let ip = &conn.remote_ip;
            if let Some(existing) = self.history.iter_mut().find(|c| c.ip_address == *ip) {
                existing.last_seen = now.clone();

                // Если включено сохранение портов в истории – обновляем их
                if self.config.monitor.include_ports_in_history {
                    if let Some(ref mut ports) = existing.ports {
                        if !ports.iter().any(|p| p.port == conn.remote_port) {
                            ports.push(PortInfo {
                                port: conn.remote_port.clone(),
                                state: conn.state.clone(),
                            });
                        } else if let Some(p) = ports.iter_mut().find(|p| p.port == conn.remote_port) {
                            p.state = conn.state.clone();
                        }
                    }
                }
            } else {
                let dir_str = match conn.direction {
                    ConnectionDirection::Incoming => "incoming",
                    ConnectionDirection::Outgoing => "outgoing",
                    ConnectionDirection::Unknown => "unknown",
                };
                let hostname = self.resolve_hostname(&conn.remote_ip);

                let _ports = if self.config.monitor.include_ports_in_history {
                    Some(vec![PortInfo {
                        port: conn.remote_port.clone(),
                        state: conn.state.clone(),
                    }])
                } else {
                    None
                };

                let saved_conn = Connection {
                    ip_address: ip.clone(),
                    hostname,
                    ports: Some(vec![PortInfo {
                        port: conn.remote_port.clone(),
                        state: conn.state.clone(),
                    }]),
                    discovered_at: now.clone(),
                    last_seen: now.clone(),
                    protocol: conn.protocol.clone(),
                    direction: dir_str.to_string(),
                    local_port: conn.local_port.clone(),
                    local_ip: conn.local_ip.clone(),
                };
                self.history.push(saved_conn);
            }
        }

        // Сохраняем всю историю в файл
        self.save_all_history()?;

        Ok((new_connections, disappeared))
    }

    fn send_alert(&self, message: &str) {
        if self.config.alerts.enable_console_alerts {
            println!("[ALERT] {}", message);
        }
        
        if self.config.alerts.enable_log_alerts {
            let _ = self.logger.alert(message);
        }
    }

    fn cleanup_old_history(&mut self) {
        let now = SystemTime::now();
        let max_age = Duration::from_secs(self.config.monitor.max_history_age_days as u64 * 24 * 60 * 60);
        let initial_count = self.history.len();
        
        self.history.retain(|conn| {
            if let Ok(parsed_time) = DateTime::parse_from_rfc3339(&conn.last_seen) {
                let last_seen_time = SystemTime::from(parsed_time);
                if let Ok(elapsed) = now.duration_since(last_seen_time) {
                    return elapsed < max_age;
                }
            }
            true
        });
        
        if initial_count != self.history.len() {
            let _ = self.logger.info(&format!(
                "Cleaned up {} old connections from history (older than {} days)",
                initial_count - self.history.len(),
                self.config.monitor.max_history_age_days
            ));
        }
    }
    
    fn export_report(&self) -> std::io::Result<()> {
        let mut file = File::create(&self.config.files.report_file)?;
        let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S");

        // Группируем историю по IP
        let mut ip_map: std::collections::HashMap<String, Vec<&Connection>> = std::collections::HashMap::new();
        for conn in &self.history {
            ip_map.entry(conn.ip_address.clone()).or_default().push(conn);
        }

        writeln!(file, "Connection Monitor Report")?;
        writeln!(file, "Generated: {}", timestamp)?;
        writeln!(file, "Configuration: {}", self.config.files.config_file)?;
        writeln!(file, "Traffic type: {:?}", self.config.monitor.traffic_type)?;

        let incoming_count = ip_map.values()
            .filter(|v| v.iter().any(|c| c.direction == "incoming"))
            .count();
        let outgoing_count = ip_map.values()
            .filter(|v| v.iter().any(|c| c.direction == "outgoing"))
            .count();

        writeln!(file, "\nStatistics:")?;
        writeln!(file, "  - Total unique hosts: {}", ip_map.len())?;
        writeln!(file, "  - Incoming: {}", incoming_count)?;
        writeln!(file, "  - Outgoing: {}", outgoing_count)?;
        writeln!(file, "  - Currently active hosts: {}",
            ip_map.iter()
                .filter(|(ip, _)| self.current_connections.contains(*ip))
                .count()
        )?;

        writeln!(file, "\nActive Hosts:")?;

        for (ip, connections) in &ip_map {
            if !self.current_connections.contains(ip) {
                continue;
            }

            // Берём самую свежую запись для получения hostname, direction и т.д.
            let latest = connections.iter()
                .max_by_key(|c| &c.last_seen)
                .unwrap();

            let hostname_str = latest.hostname.as_deref().unwrap_or("N/A");

            writeln!(file, "  {} ({})", ip, hostname_str)?;
            writeln!(file, "    Local: {}:{}", latest.local_ip, latest.local_port)?;
            writeln!(file, "    Direction: {}", latest.direction)?;
            writeln!(file, "    Last seen: {}", latest.last_seen)?;

            // Показываем порты, только если они есть в истории (include_ports_in_history = true)
            if let Some(ref ports) = latest.ports {
                if !ports.is_empty() {
                    let port_desc: Vec<String> = ports.iter()
                        .map(|p| format!("{} ({})", p.port, p.state))
                        .collect();
                    writeln!(file, "    Ports: {}", port_desc.join(", "))?;
                }
            }
        }

        Ok(())
    }

    fn resolve_hostname(&self, ip: &str) -> Option<String> {
        if !self.config.monitor.resolve_dns {
            return None;
        }

        let clean_ip = ip.trim_start_matches('[')
                        .trim_end_matches(']')
                        .split(':')
                        .next()
                        .unwrap_or(ip);

        // Check private ip address
        if self.config.monitor.resolve_only_private && !Self::is_private_ip(clean_ip) {
            return None;
        }

        let addr: IpAddr = clean_ip.parse().ok()?;

        // Простой резолвинг без таймаута (можно обернуть в thread::spawn для таймаута)
        lookup_addr(&addr).ok()
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    let args: Vec<String> = env::args().collect();
    let mut config_path = "config.toml".to_string();
    
    for i in 1..args.len() {
        match args[i].as_str() {
            "--config" if i + 1 < args.len() => {
                config_path = args[i + 1].clone();
            }
            "--debug" => {
                println!("Debug mode enabled");
            }
            _ => {}
        }
    }
    
    let config = match AppConfig::load_from_file(&config_path) {
        Ok(cfg) => {
            println!("Configuration loaded from {}", config_path);
            cfg
        }
        Err(e) => {
            eprintln!("Failed to load {}: {}. Creating default config.", config_path, e);
            let default_config = AppConfig::new()?;
            default_config.create_default_config()?;
            default_config
        }
    };
    
    let monitor = Arc::new(Mutex::new(ConnectionMonitor::new(config.clone())));

    {
        let mon = monitor.lock().unwrap();
        let _ = mon.logger.info(&format!(
            "Starting Connection Monitor"
        ));
        let _ = mon.logger.info(&format!(
            "Check interval: {}s, Alert interval: {}min, Traffic type: {:?}",
            config.monitor.check_interval_seconds,
            config.monitor.alert_interval_minutes,
            config.monitor.traffic_type
        ));
    }
    
    {
        let mut mon = monitor.lock().unwrap();
        if let Err(e) = mon.load_history() {
            let _ = mon.logger.error(&format!("Failed to load history: {}", e));
        }
    }
    
    let mut iteration = 0;
    let check_interval = Duration::from_secs(config.monitor.check_interval_seconds);
    let export_interval = if config.monitor.export_report_interval > 0 {
        config.monitor.export_report_interval / config.monitor.check_interval_seconds
    } else {
        0
    };
    
    loop {
        iteration += 1;
        
        let (new_connections, disappeared) = {
            let mut mon = monitor.lock().unwrap();

            match mon.check_connections() {
                Ok((new, disappeared)) => {
                    if mon.config.alerts.alert_on_disconnection {
                        for ip in &disappeared {
                            if let Some(conn) = mon.history.iter().find(|c| c.ip_address == *ip) {
                                // Собираем описание портов только если включена опция
                                let ports_part = if mon.config.monitor.show_ports_in_logs {
                                if let Some(ref ports) = conn.ports {
                                    let desc: Vec<String> = ports.iter()
                                        .map(|p| format!("{} ({})", p.port, p.state))
                                        .collect();
                                    format!(" | Ports: {}", desc.join(", "))
                                } else {
                                    String::new()
                                }
                            } else {
                                String::new()
                            };

                                let message = format!(
                                    "Connection disappeared: {} [{}] | Direction: {}{} | First seen: {}",
                                    conn.ip_address,
                                    conn.protocol,
                                    conn.direction,
                                    ports_part,
                                    conn.discovered_at
                                );
                                mon.send_alert(&message);
                            }
                        }
                    }

                    mon.cleanup_old_history();

                    (new, disappeared)
                }
                Err(e) => {
                    let _ = monitor.lock().unwrap().logger.error(&format!("Error checking connections: {}", e));
                    (Vec::new(), Vec::new())
                }
            }
        };
        
        {
            let mon = monitor.lock().unwrap();
            let _ = mon.logger.info(&format!(
                "Iteration {}: Active={}, New={}, Disappeared={}, History={}",
                iteration,
                mon.current_connections.len(),
                new_connections.len(),
                disappeared.len(),
                mon.history.len()
            ));
        }
        
        if export_interval > 0 && iteration % export_interval == 0 {
            if let Err(e) = monitor.lock().unwrap().export_report() {
                let _ = monitor.lock().unwrap().logger.error(&format!("Failed to export report: {}", e));
            }
        }
        
        thread::sleep(check_interval);
    }
}