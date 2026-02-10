# DeepShield Browser Extension

πŸ›'οΈ **AI-Powered Phishing Protection for Chrome & Firefox**

![Version](https://img.shields.io/badge/version-1.0.0-blue)
![Manifest](https://img.shields.io/badge/manifest-v3-green)
![License](https://img.shields.io/badge/license-MIT-orange)

## Features

- πŸ" **Real-time URL Analysis** - Checks every URL before navigation
- 🧠 **AI-Powered Detection** - Uses XGBoost + Deep Learning models (99.8% accuracy)
- ⚑ **Cascaded Inference** - Fast path for quick decisions, deep analysis when needed
- πŸ›'οΈ **Block/Warn/Allow** - Graduated response based on threat confidence
- πŸ" **Explainable AI** - See why a URL was flagged
- πŸ"΄ **Offline Fallback** - Trusted domain whitelist when API is unavailable
- 🎨 **Modern UI** - Beautiful glassmorphism design

## Installation

### Chrome (Developer Mode)

1. Open `chrome://extensions/`
2. Enable **Developer mode** (top right toggle)
3. Click **Load unpacked**
4. Select the `extension` folder

### Firefox (Developer Mode)

1. Open `about:debugging#/runtime/this-firefox`
2. Click **Load Temporary Add-on**
3. Select `manifest.json` from the `extension` folder

## Configuration

### API Endpoint

By default, the extension connects to `http://localhost:8000`. To change:

1. Click the extension icon
2. Go to **Settings**
3. Update the **API Endpoint** field

### Starting the API Server

```bash
# From the DeepShield root directory
cd p:\DeepShield
python src/api_new.py
```

The API will be available at `http://localhost:8000`.

## Files

```
extension/
β"œβ"€β"€ manifest.json      # Chrome Manifest V3 configuration
β"œβ"€β"€ background.js      # Service worker (URL interception, API calls)
β"œβ"€β"€ content.js         # Content script (warning overlays)
β"œβ"€β"€ content.css        # Content script styles
β"œβ"€β"€ popup/
β"‚   β"œβ"€β"€ popup.html     # Extension popup UI
β"‚   β"œβ"€β"€ popup.css      # Popup styles (glassmorphism theme)
β"‚   └── popup.js       # Popup logic
β"œβ"€β"€ options/
β"‚   └── options.html   # Settings page
└── icons/
    β"œβ"€β"€ icon-16.svg    # Toolbar icon
    β"œβ"€β"€ icon-48.svg    # Extension management icon
    └── icon-128.svg   # Web store icon
```

## How It Works

```
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
β"ƒ  User navigates to URL                                                  β"ƒ
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
                                    β"‚
                                    β–Ό
              ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
              β"ƒ  background.js intercepts navigation  β"ƒ
              ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
                                    β"‚
                     β"Œβ"€β"€β"€β"€β"€β"€β"€β"€β"€β"€β"€β"€β"€β"€β"Όβ"€β"€β"€β"€β"€β"€β"€β"€β"€β"€β"€β"€β"€β"€β"
                     β"‚              β"‚              β"‚
                     β–Ό              β–Ό              β–Ό
            ┏━━━━━━━━━━━━━┓  ┏━━━━━━━━━━━━━┓  ┏━━━━━━━━━━━━━┓
            β"ƒ Check Cache β"ƒ  β"ƒ Trusted List β"ƒ  β"ƒ Call API    β"ƒ
            ┗━━━━━━━━━━━━━┛  ┗━━━━━━━━━━━━━┛  ┗━━━━━━━━━━━━━┛
                                                    β"‚
                                                    β–Ό
                                    ┏━━━━━━━━━━━━━━━━━━━━━━━━━━┓
                                    β"ƒ  XGBoost (Fast Path)    β"ƒ
                                    β"ƒ  β"Œβ"€β"€β"€β"€β"€β"€β"€β"€β"€β"€β"€β"€β"€β"€β"€β"€β"€β"€β"€β"€β"€β" β"ƒ
                                    β"ƒ  β"‚ Confidence > 95%?  β"‚ β"ƒ
                                    β"ƒ  β""β"€β"€β"€β"€β"€β"€β"€β"€β"€β"€β"€β"€β"€β"€β"€β"€β"€β"€β"€β"€β"€β"˜ β"ƒ
                                    ┗━━━━━━━━━━━━━━━━━━━━━━━━━━┛
                                         β"‚           β"‚
                              Yes β"Œβ"€β"€β"€β"€β"€β"€β"˜           β""β"€β"€β"€β"€β"€β"€β" No
                                  β–Ό                         β–Ό
                         ┏━━━━━━━━━━━━━━━━┓        ┏━━━━━━━━━━━━━━━━┓
                         β"ƒ Return Verdict β"ƒ        β"ƒ Deep Learning  β"ƒ
                         ┗━━━━━━━━━━━━━━━━┛        β"ƒ Ensemble       β"ƒ
                                                  ┗━━━━━━━━━━━━━━━━┛
                                                         β"‚
                                                         β–Ό
                                              ┏━━━━━━━━━━━━━━━━━━┓
                                              β"ƒ Final Verdict    β"ƒ
                                              ┗━━━━━━━━━━━━━━━━━━┛
```

## Verdict Levels

| Status | Color | Confidence | Action |
|--------|-------|------------|--------|
| **Blocked** | 🟒 Red | β‰₯80% | Page blocked with full-screen warning |
| **Warning** | 🟑 Yellow | 50-80% | Overlay with proceed option |
| **Safe** | 🟒 Green | <50% | Green badge, normal browsing |

## Privacy

- **No tracking** - URLs are analyzed but not logged permanently
- **Local caching** - Reduces repeated API calls
- **Offline mode** - Falls back to trusted domain list

## Development

### Building for Production

The extension is ready to use as-is. For Chrome Web Store submission:

1. Remove any development-only permissions
2. Zip the `extension` folder
3. Submit to [Chrome Web Store Developer Dashboard](https://chrome.google.com/webstore/devconsole)

### Testing

```bash
# Run API tests
pytest tests/test_api.py -v

# Run adversarial tests (requires API running)
pytest tests/test_adversarial.py -v
```

## License

MIT License - See [LICENSE](../LICENSE) for details.

## Support

- **Issues**: Report bugs on GitHub
- **Docs**: See main DeepShield README
- **API Docs**: http://localhost:8000/docs (when running)
