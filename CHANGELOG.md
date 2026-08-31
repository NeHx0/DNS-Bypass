# Changelog

All notable changes to DNS Bypass will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [2.5.0] - 2026-08-31

### 🎉 Major Release - Modular Architecture & Backup System

### Added
- **Modular Core Architecture**
  - Interface-based design (ILogger, IRegistryManager, INetworkHardener, IBackupService, IRestoreService)
  - Separated concerns into Core/{Interfaces, Models, Helpers, Services}
  - Dependency injection ready

- **Network Hardening (Sprint 1)**
  - NetBIOS over TCP/IP disable (all adapters)
  - IPv6 transition technologies disable (Teredo, ISATAP, 6to4, IP-HTTPS)
  - DNS cache optimization (negative TTL, max cache limits)
  - NCSI probes disable (active + passive)
  - DNS client hardening (DoH required, LLMNR off, smart resolution off)
  - Menu option [7] Network Hardening

- **Backup & Restore System (Sprint 2)**
  - System snapshot creation (registry + DNS + services)
  - JSON-based backup storage
  - Snapshot validation and compatibility checking
  - Full/partial restore with dry-run support
  - Menu option [8] Backup System
  - Menu option [9] Restore from Backup

- **Configuration Management**
  - JSON-based configuration (config.json)
  - Legacy settings.ini migration
  - Provider management API
  - Custom DNS configuration

- **Services**
  - `SafeRegistryHelper`: Thread-safe registry operations
  - `NetworkHardener`: Comprehensive DNS leak prevention
  - `BackupService`: Snapshot management with JSON serialization
  - `RestoreService`: Safe restoration with validation
  - `ConfigurationService`: Modern configuration management
  - `ConsoleLogger`: Colored, time-stamped logging

### Changed
- Namespace changed from `BlockerKiller` to `DnsAdvancedBypass`
- Application name changed from "Blocker Killer" to "DNS Bypass"
- Moved model classes to Core/Models
- Refactored Program.cs for modularity
- Menu expanded from 7 to 10 options

### Improved
- Thread-safe registry operations with locking
- Comprehensive error handling throughout
- Async/await pattern in services
- Clean Code principles and SOLID architecture
- XML documentation on all public APIs

---

## [2.4.0] - 2026-08-28

### Added
- MAC address-based hardware lock (PC + phone MAC)
- Enhanced DNS verification with live queries
- DoH (DNS-over-HTTPS) enforcement
- Registry persistence for DNS settings

### Changed
- Improved DNS application reliability with retries
- Better error messages and user feedback

---

## [2.3.0] - 2026-08-27

### Added
- DNS provider selection (10 providers)
- Custom DNS server support
- IPv6 DNS configuration
- Website connectivity testing
- Status check with leak detection

### Fixed
- DNS apply failures on some adapters
- IPv6 DNS not being set correctly

---

## [2.0.0] - 2026-08-26

### Added
- Initial release
- Basic DNS bypass functionality
- Cloudflare and Google DNS support
- Simple backup/restore
- CLI mode support

---

## Roadmap

### [3.0.0] - Planned
- [ ] CLI parameter expansion (--backup, --restore, --harden)
- [ ] Auto-backup before hardening
- [ ] Backup rotation (max 10 snapshots)
- [ ] Backup comparison tool
- [ ] GitHub Actions CI/CD
- [ ] Automated testing

### [3.5.0] - Future
- [ ] Local HTTP proxy (proof of concept)
- [ ] Traffic obfuscation research
- [ ] Performance metrics
- [ ] Configuration import/export UI

---

## Legend

- 🎉 Major Release
- ✨ New Feature
- 🐛 Bug Fix
- 🔧 Improvement
- 📝 Documentation
- ⚠️ Breaking Change
