# 🔍 Naminter

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

The most powerful and fast username availability checker that searches across hundreds of websites using [WhatsMyName](https://github.com/WebBreacher/WhatsMyName) dataset. Naminter features full support of WhatsMyName data scheme, a beautiful console interface, browser impersonating, concurrent checking, and extensive configuration options.

## ✨ Features

- Full support of [WhatsMyName](https://github.com/WebBreacher/WhatsMyName) data scheme and updates
- Check username availability across 600+ websites from WhatsMyName database
- Accurate browser impersonation for enhanced detection
- Beautiful real-time console interface with progress tracking
- Fast concurrent checking with customizable concurrency
- Category-based filtering of websites
- Support for custom website lists (local and remote) in WhatsMyName format
- Proxy support with configurable settings
- Self-test functionality to validate detection methods
- Weak matching mode for fuzzy detection

## 🚀 Installation

```bash
pip install naminter
```

Or install from source:

```bash
git clone https://github.com/username/naminter.git
cd naminter
pip install -e .
```

## 💡 Usage

Basic usage:

```bash
naminter username
```

Advanced usage with options:

```bash
naminter username \
    --max-tasks 50 \
    --timeout 30 \
    --impersonate chrome \
    --include-categories social,tech \
    --proxy http://proxy:8080
```

### 🎯 Command Line Options

| Option | Description |
|--------|-------------|
| `username` | Username to check |
| `-m, --max-tasks` | Maximum concurrent tasks (default: 50) |
| `-t, --timeout` | Request timeout in seconds (default: 30) |
| `-i, --impersonate` | Browser to impersonate (none/chrome/chrome_android/safari/safari_ios/edge) |
| `-ic, --include-categories` | Categories to include |
| `-ec, --exclude-categories` | Categories to exclude |
| `-p, --proxy` | Proxy URL |
| `-l, --local-list` | Path to local website list |
| `-r, --remote-url` | URL to remote website list |
| `-w, --weak` | Enable weak matching mode |
| `--allow-redirects` | Allow HTTP redirects |
| `--verify-ssl` | Verify SSL certificates |
| `--self-check` | Run self-test mode |
| `-d, --debug` | Enable debug output |
| `--no-color` | Disable colored output |

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
