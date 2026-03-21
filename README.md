# Alice Miner

Desktop client for Alice Protocol decentralized AI training network.

## Prerequisites

- Node.js 18+
- Rust 1.75+
- Platform-specific requirements:
  - **Windows**: MSVC Build Tools, WebView2
  - **macOS**: Xcode Command Line Tools
  - **Linux**: `libwebkit2gtk-4.0-dev`, `libssl-dev`, `libgtk-3-dev`

## Development Setup

```bash
# Install Node dependencies
npm install

# Run in development mode
npm run tauri dev

# Build for production
npm run tauri build
```

## Project Structure

```
alice-miner/
├── src/                    # React frontend
│   ├── pages/              # Page components
│   ├── components/         # Reusable components
│   ├── hooks/              # React hooks & state
│   └── styles/             # CSS styles
├── src-tauri/              # Rust backend
│   ├── src/
│   │   ├── commands/       # Tauri commands
│   │   │   ├── network.rs  # Network diagnostics
│   │   │   ├── gpu.rs      # GPU detection
│   │   │   ├── wallet.rs   # Wallet management
│   │   │   ├── mining.rs   # Mining process
│   │   │   └── model.rs    # Model download
│   │   └── services/       # Background services
│   └── tauri.conf.json     # Tauri configuration
└── package.json
```

## Features

### Phase 1 (Current)
- [x] Network diagnostics (PS connection, latency, bandwidth)
- [x] GPU detection (NVIDIA/Apple Silicon)
- [x] Model download with resume support
- [x] Wallet creation/import
- [x] Mining start/stop
- [x] Real-time status dashboard

### Phase 2 (Planned)
- [ ] Earnings tracking
- [ ] System tray integration
- [ ] Auto-updates
- [ ] Multi-language support

## Build

### Windows
```bash
npm run tauri build
# Output: src-tauri/target/release/bundle/msi/
```

### macOS
```bash
npm run tauri build
# Output: src-tauri/target/release/bundle/dmg/
```

### Linux
```bash
npm run tauri build
# Output: src-tauri/target/release/bundle/appimage/
```

## Notes

- The miner binary (`alice-miner-core`) needs to be built separately using PyInstaller
- Model files are downloaded on first run (~7GB for INT8, ~13GB for FP16)
- Wallet addresses use Alice Protocol's SS58 prefix (300), starting with 'a'

## License

MIT
