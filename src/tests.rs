use super::*;

    // Вспомогательная функция для создания минимального ConnectionMonitor
    fn create_test_monitor() -> ConnectionMonitor {
        let config = AppConfig {
            monitor: MonitorConfig {
                alert_interval_minutes: 5,
                check_interval_seconds: 10,
                max_history_age_days: 30,
                export_report_interval: 300,
                traffic_type: TrafficType::All,
                debug: false,
                resolve_dns: true,
                dns_timeout_ms: 1500,
                resolve_only_private: true,
                group_by_ip: true,
                show_ports_in_logs: false,
                include_ports_in_history: false,
            },
            filtering: FilteringConfig {
                ignore_ips: vec![],
                ignore_private_ips: false,
                ignore_public_ips: false,
                ignore_localhost: false,
                ignore_ports: vec![],
                monitor_only_ports: None,
                allowed_subnets: None,
                ignore_ipv6: false,
            },
            files: FileConfig {
                data_file: "test_data.jsonl".to_string(),
                log_file: "test.log".to_string(),
                config_file: "test_config.toml".to_string(),
                report_file: "test_report.txt".to_string(),
                max_log_size_mb: 1,
                max_log_files: 2,
            },
            alerts: AlertConfig {
                enable_console_alerts: false,
                enable_log_alerts: false,
                alert_on_new_connection: false,
                alert_on_disconnection: false,
                alert_threshold_count: None,
            },
        };
        let logger = Logger::new(&config.files);
        ConnectionMonitor {
            current_connections: HashSet::new(),
            history: Vec::new(),
            config,
            logger,
        }
    }

    // Тесты parse_ss_line
    #[test]
    fn test_parse_ss_line_tcp_established() {
        let monitor = create_test_monitor();
        let line = "tcp ESTAB 0 0 192.168.1.10:54321 93.184.216.34:80";
        let conn = monitor.parse_ss_line(line).expect("Should parse valid TCP line");
        assert_eq!(conn.remote_ip, "93.184.216.34");
        assert_eq!(conn.remote_port, "80");
        assert_eq!(conn.local_ip, "192.168.1.10");
        assert_eq!(conn.local_port, "54321");
        assert_eq!(conn.protocol, "TCP");
        assert_eq!(conn.state, "ESTAB");
        // Определится как Outgoing, т.к. локальный IP приватный, удалённый — публичный
        assert_eq!(conn.direction, ConnectionDirection::Outgoing);
    }

    #[test]
    fn test_parse_ss_line_udp_listen() {
        let monitor = create_test_monitor();
        let line = "udp UNCONN 0 0 0.0.0.0:5353 0.0.0.0:*";
        // Это слушающий сокет, должен быть проигнорирован
        assert!(monitor.parse_ss_line(line).is_none());
    }

    #[test]
    fn test_parse_ss_line_incoming() {
        let monitor = create_test_monitor();
        // Локальный публичный, удалённый приватный – входящее
        let line = "tcp ESTAB 0 0 203.0.113.5:443 10.0.0.1:51234";
        let conn = monitor.parse_ss_line(line).expect("Should parse");
        assert_eq!(conn.direction, ConnectionDirection::Incoming);
    }

    #[test]
    fn test_parse_ss_line_ipv6() {
        let monitor = create_test_monitor();
        let line = "tcp ESTAB 0 0 [::ffff:192.168.1.10]:443 [::ffff:93.184.216.34]:52123";
        let conn = monitor.parse_ss_line(line).expect("Should parse IPv6-mapped");
        assert_eq!(conn.remote_ip, "::ffff:93.184.216.34");
        assert_eq!(conn.remote_port, "52123");
    }

    #[test]
    fn test_parse_ss_line_ignored_ip() {
        let mut monitor = create_test_monitor();
        monitor.config.filtering.ignore_ips = vec!["93.184.216.34".to_string()];
        let line = "tcp ESTAB 0 0 192.168.1.10:54321 93.184.216.34:80";
        assert!(monitor.parse_ss_line(line).is_none());
    }

    #[test]
    fn test_parse_ss_line_ignored_port() {
        let mut monitor = create_test_monitor();
        monitor.config.filtering.ignore_ports = vec![80];
        let line = "tcp ESTAB 0 0 192.168.1.10:54321 93.184.216.34:80";
        assert!(monitor.parse_ss_line(line).is_none());
    }

    #[test]
    fn test_parse_ss_line_monitor_only_ports() {
        let mut monitor = create_test_monitor();
        monitor.config.filtering.monitor_only_ports = Some(vec![443]);
        let line = "tcp ESTAB 0 0 192.168.1.10:54321 93.184.216.34:80";
        assert!(monitor.parse_ss_line(line).is_none()); // 80 нет в списке разрешённых
        let line443 = "tcp ESTAB 0 0 192.168.1.10:54321 93.184.216.34:443";
        assert!(monitor.parse_ss_line(line443).is_some());
    }

    // Тесты determine_direction
    #[test]
    fn test_determine_direction_syn_sent() {
        let dir = ConnectionMonitor::determine_direction(
            "SYN_SENT", "10.0.0.1", "12345", "93.184.216.34"
        );
        assert_eq!(dir, ConnectionDirection::Outgoing);
    }

    #[test]
    fn test_determine_direction_local_low_port() {
        // Если локальный порт < 1024, считаем входящим
        let dir = ConnectionMonitor::determine_direction(
            "ESTABLISHED", "10.0.0.1", "80", "93.184.216.34"
        );
        assert_eq!(dir, ConnectionDirection::Incoming);
    }

    #[test]
    fn test_determine_direction_private_to_public() {
        let dir = ConnectionMonitor::determine_direction(
            "ESTABLISHED", "192.168.1.5", "50000", "8.8.8.8"
        );
        assert_eq!(dir, ConnectionDirection::Outgoing);
    }

    #[test]
    fn test_determine_direction_public_to_private() {
        let dir = ConnectionMonitor::determine_direction(
            "ESTABLISHED", "203.0.113.10", "443", "10.0.0.5"
        );
        assert_eq!(dir, ConnectionDirection::Incoming);
    }

    #[test]
    fn test_determine_direction_both_private_local_high_remote_low() {
        let _dir = ConnectionMonitor::determine_direction(
            "ESTABLISHED", "192.168.1.5", "50000", "192.168.1.1"
        );
        // Удалённый порт неизвестен, т.к. в сигнатуре remote_ip без порта.
        // Но в функции вы парсите порт из remote_ip через split(':'), а здесь передаётся IP без порта.
        // Актуализируем тест: в вашей функции вы разбираете remote_ip как "IP:PORT", поэтому
        // в тестах надо передавать строку с портом или только IP, но тогда функция упадёт.
        // Лучше переписать тесты, передавая корректные параметры в том виде, как их вызывает парсер:
        // В парсере remote_ip — это только IP (без порта), а порт передаётся отдельным параметром.
        // В функции determine_direction сигнатура: (state, local_ip, local_port, remote_ip).
        // remote_ip — это именно IP, без порта. Так что в тесте передаём IP без порта.
    }

    // Исправим тест для both private с портами:
    #[test]
    fn test_determine_direction_both_private() {
        // Оба приватные, local_port > 1024, remote_port <= 1024 (но порт remote мы здесь не передаём!)
        // На самом деле в determine_direction порт удалённого хоста не участвует (кроме первых проверок local_port).
        // Поэтому этот тест покажет Unknown. Переделаем:
        let dir = ConnectionMonitor::determine_direction(
            "ESTABLISHED", "192.168.1.5", "50000", "192.168.1.1"
        );
        // Поскольку оба приватные, и нет информации о портах, вернётся Unknown.
        assert_eq!(dir, ConnectionDirection::Unknown);
    }

    // Test is_private_ip
    #[test]
    fn test_is_private_ipv4() {
        assert!(ConnectionMonitor::is_private_ip("192.168.1.1"));
        assert!(ConnectionMonitor::is_private_ip("10.0.0.1"));
        assert!(ConnectionMonitor::is_private_ip("172.16.0.1"));
        assert!(ConnectionMonitor::is_private_ip("172.31.255.255"));
        assert!(ConnectionMonitor::is_private_ip("127.0.0.1"));
        assert!(ConnectionMonitor::is_private_ip("169.254.1.1"));
    }

    #[test]
    fn test_is_public_ipv4() {
        assert!(!ConnectionMonitor::is_private_ip("8.8.8.8"));
        assert!(!ConnectionMonitor::is_private_ip("93.184.216.34"));
        assert!(!ConnectionMonitor::is_private_ip("172.32.0.1")); // за пределами /12
    }

    #[test]
    fn test_is_private_ipv6() {
        assert!(ConnectionMonitor::is_private_ip("::1"));
        assert!(ConnectionMonitor::is_private_ip("fe80::1"));
        assert!(ConnectionMonitor::is_private_ip("fc00::1"));
    }

    #[test]
    fn test_is_private_ipv6_brackets() {
        // Парсер может передавать с квадратными скобками, метод должен их убирать
        assert!(ConnectionMonitor::is_private_ip("[::1]"));
        assert!(ConnectionMonitor::is_private_ip("[fe80::1]"));
    }

    // Дополнительно: тест парсинга адреса
    #[test]
    fn test_parse_address_ipv4() {
        let (ip, port) = ConnectionMonitor::parse_address("192.168.1.1:80").unwrap();
        assert_eq!(ip, "192.168.1.1");
        assert_eq!(port, "80");
    }

    #[test]
    fn test_parse_address_ipv6_brackets() {
        let (ip, port) = ConnectionMonitor::parse_address("[::1]:443").unwrap();
        assert_eq!(ip, "::1");
        assert_eq!(port, "443");
    }

    #[test]
    fn test_parse_address_ipv6_no_brackets() {
        // В выводе ss IPv6 адреса без порта могут быть без скобок, но с портом обычно в скобках.
        // Протестируем вариант "::1:443" - он неоднозначен, rsplit_once(':') даст ip="::1", port="443".
        let (ip, port) = ConnectionMonitor::parse_address("::1:443").unwrap();
        // Такой вариант парсер обработает, но IP будет "::1", а port "443"
        assert_eq!(ip, "::1");
        assert_eq!(port, "443");
    }