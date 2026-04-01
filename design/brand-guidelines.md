# MCP Audit — Brand Guidelines

## 1. Tożsamość marki

**Nazwa:** MCP Audit
**Tagline:** *npm audit for MCP servers*
**Pozycjonowanie:** Jedyne dedykowane narzędzie bezpieczeństwa dla ekosystemu MCP. Profesjonalne, zaufane, open source.

**Osobowość marki:**
- **Autorytatywna** — bazujemy na OWASP MCP Top 10
- **Przejrzysta** — open source, jasne wyniki, zero BS
- **Techniczna** — narzędzie dla developerów, nie dla marketingu
- **Ochronna** — tarcza, bezpieczeństwo, skanowanie

---

## 2. Logo

### Koncept
Logo łączy motyw **tarczy** (ochrona/bezpieczeństwo) z **skanera** (linie skanujące / radar).
Centralna ikona to tarcza z wbudowanymi liniami skanowania, symbolizująca aktywną ochronę.

### Warianty
| Wariant | Plik | Użycie |
|---------|------|--------|
| Logo pełne (ikona + tekst) | `logo-full.svg` | README, strona, prezentacje |
| Ikona (mark) | `logo-icon.svg` | Favicon, avatar, badge, małe rozmiary |
| Monochrome | `logo-mono-white.svg` | Na ciemnym tle |
| Monochrome | `logo-mono-dark.svg` | Na jasnym tle |

### Zasady użycia
- Minimalna wielkość ikony: 24×24 px
- Minimalna wielkość pełnego logo: 120×32 px
- Zawsze zachowuj proporcje (nie rozciągaj)
- Minimum padding: 1/4 szerokości ikony dookoła
- NIE obracaj, nie dodawaj efektów, nie zmieniaj kolorów poza paletą

---

## 3. Paleta kolorów

### Kolory główne (Primary)

| Nazwa | Hex | RGB | Użycie |
|-------|-----|-----|--------|
| **Scanner Dark** | `#0D1117` | 13, 17, 23 | Główne tło, ciemny motyw |
| **Scanner Deep** | `#161B22` | 22, 27, 34 | Tło kart, sekcji |
| **Shield Blue** | `#2F81F7` | 47, 129, 247 | Główny accent, linki, CTA |
| **Shield Bright** | `#58A6FF` | 88, 166, 255 | Hover, secondary accent |

### Kolory statusów (Semantic)

| Nazwa | Hex | RGB | Użycie |
|-------|-----|-----|--------|
| **Pass Green** | `#3FB950` | 63, 185, 80 | Passed, secure, no issues |
| **Warn Yellow** | `#D29922` | 210, 153, 34 | Warning, medium severity |
| **Fail Red** | `#F85149` | 248, 81, 73 | Failed, critical, high severity |
| **Info Gray** | `#8B949E` | 139, 148, 158 | Informational, secondary text |

### Kolory severity (mapowanie na OWASP)

| Severity | Kolor | Hex | Badge |
|----------|-------|-----|-------|
| Critical | Deep Red | `#DA3633` | Pulsujący czerwony |
| High | Red | `#F85149` | Czerwony |
| Medium | Yellow | `#D29922` | Żółty |
| Low | Blue | `#58A6FF` | Niebieski |
| Info | Gray | `#8B949E` | Szary |

### Tła i powierzchnie

| Element | Hex | Opis |
|---------|-----|------|
| Background | `#0D1117` | Główne tło (dark mode) |
| Surface | `#161B22` | Karty, panele |
| Border | `#30363D` | Obramowania, separatory |
| Text Primary | `#F0F6FC` | Główny tekst |
| Text Secondary | `#8B949E` | Tekst pomocniczy |
| Text Muted | `#484F58` | Tekst nieaktywny |

> **Rationale:** Paleta inspirowana GitHub Dark theme — naturalne środowisko developerów.
> Ciemne tło = bezpieczeństwo, profesjonalizm. Zielony/czerwony = natychmiastowy feedback pass/fail.

---

## 4. Typografia

### Fonty

| Kontekst | Font | Fallback | Styl |
|----------|------|----------|------|
| **Logo / Headings** | **Inter** | system-ui, -apple-system, sans-serif | Bold (700), Semi-Bold (600) |
| **Body** | **Inter** | system-ui, -apple-system, sans-serif | Regular (400), Medium (500) |
| **Code / CLI output** | **JetBrains Mono** | 'Fira Code', 'SF Mono', monospace | Regular (400) |
| **Badges** | **Inter** | sans-serif | Semi-Bold (600) |

### Hierarchia

| Element | Rozmiar | Waga | Kolor |
|---------|---------|------|-------|
| H1 (hero) | 48px / 3rem | Bold 700 | `#F0F6FC` |
| H2 (sekcja) | 32px / 2rem | Semi-Bold 600 | `#F0F6FC` |
| H3 (podsekcja) | 24px / 1.5rem | Semi-Bold 600 | `#F0F6FC` |
| Body | 16px / 1rem | Regular 400 | `#C9D1D9` |
| Small / Caption | 14px / 0.875rem | Regular 400 | `#8B949E` |
| Code inline | 14px / 0.875rem | Regular 400 | `#F0F6FC` on `#161B22` |
| CLI output | 14px / 0.875rem | Regular 400 | `#3FB950` (green on dark) |

---

## 5. Ikony i elementy wizualne

### Styl ikon
- Outline (nie filled) — nawiązanie do stylu skanera/wireframe
- Grubość linii: 1.5px (consistent)
- Zaokrąglone narożniki (border-radius: 2px)
- Rozmiar bazowy: 24×24 px

### Ikony severity
- 🔴 Critical: Filled circle, pulsing
- 🟠 High: Filled triangle (warning)
- 🟡 Medium: Outlined triangle
- 🔵 Low: Outlined circle (info)
- ⚪ Info: Outlined circle (dimmed)

### Animacje CLI
- Spinner skanowania: `⠋ ⠙ ⠹ ⠸ ⠼ ⠴ ⠦ ⠧ ⠇ ⠏` (braille dots)
- Progress bar: `█░` z procentem
- Status checkmarks: `✓` (zielony) / `✗` (czerwony)

---

## 6. Social Media

### Twitter / X Banner
- Rozmiar: 1500×500 px
- Layout: Logo po lewej, tagline po prawej
- Tło: Gradient `#0D1117` → `#161B22`
- Accent: `#2F81F7` glow effect za tarczą
- Plik: `design/social/twitter-banner.svg`

### GitHub Social Preview
- Rozmiar: 1280×640 px
- Layout: Centered logo + tagline + stats
- Tło: `#0D1117`
- CTA: `cargo install mcp-audit`
- Plik: `design/social/github-social.svg`

### OpenGraph Image (og:image)
- Rozmiar: 1200×630 px
- Layout: Logo + "npm audit for MCP servers" + kluczowe features
- Plik: `design/social/og-image.svg`

---

## 7. Badge ("Scanned by MCP Audit")

### Warianty
| Status | Kolor | Tekst |
|--------|-------|-------|
| Passed | `#3FB950` | "MCP Audit | passed" |
| Failed | `#F85149` | "MCP Audit | failed" |
| Scanning | `#D29922` | "MCP Audit | scanning" |
| Unknown | `#8B949E` | "MCP Audit | unknown" |

### Format
- Styl: shields.io compatible (flat, flat-square)
- Lewa strona: Logo + "MCP Audit" na `#30363D`
- Prawa strona: Status na kolorze statusu
- Rozmiar: dynamiczny, proporcjonalny do tekstu
- Pliki: `design/badges/badge-passed.svg`, `badge-failed.svg`, etc.

### Pliki badges
| Status | Plik |
|--------|------|
| Passed | `design/badges/badge-passed.svg` |
| Failed | `design/badges/badge-failed.svg` |
| Scanning | `design/badges/badge-scanning.svg` |
| Unknown | `design/badges/badge-unknown.svg` |

### Użycie w README
```markdown
<!-- Lokalne badge SVG -->
![MCP Audit - Passed](design/badges/badge-passed.svg)
![MCP Audit - Failed](design/badges/badge-failed.svg)

<!-- shields.io (z base64 logo — wygeneruj z logo-icon.svg) -->
![MCP Audit](https://img.shields.io/badge/MCP_Scanner-passed-3FB950?logo=data:image/svg+xml;base64,...)
![MCP Audit](https://img.shields.io/badge/MCP_Scanner-failed-F85149?logo=data:image/svg+xml;base64,...)
```

---

## 8. CLI Output Branding

### Kolorowanie terminala (ANSI)
```
Scanner header:  Bold + Blue (#2F81F7)
Rule name:       Bold + White
Severity:
  Critical:      Bold + Red (#DA3633)
  High:          Red (#F85149)
  Medium:        Yellow (#D29922)
  Low:           Blue (#58A6FF)
  Info:          Dim (#8B949E)
Pass:            Green (#3FB950) + ✓
Fail:            Red (#F85149) + ✗
```

### Przykładowy output
```
  MCP Audit v0.1.0
  ═══════════════════════════════════════

  Scanning: claude_desktop_config.json
  Rules loaded: 10 (OWASP MCP Top 10)

  ┌──────────┬──────────────────────────┬──────────┬────────────────────────────┐
  │ Severity │ Rule                     │ Server   │ Finding                    │
  ├──────────┼──────────────────────────┼──────────┼────────────────────────────┤
  │ CRITICAL │ MCP-04: Insecure Creds   │ my-mcp   │ Hardcoded API key found    │
  │ HIGH     │ MCP-02: Excessive Perms  │ fs-mcp   │ Access to / (root fs)      │
  │ MEDIUM   │ MCP-06: Insecure Deps    │ npm-mcp  │ Unpinned npx package       │
  └──────────┴──────────────────────────┴──────────┴────────────────────────────┘

  Summary: 3 findings (1 critical, 1 high, 1 medium)
  Status: ✗ FAILED
```

---

## 9. Materiały do druku / prezentacji

### Slajdy
- Tło: `#0D1117`
- Tekst: `#F0F6FC`
- Accent: `#2F81F7`
- Ratio: 16:9
- Font: Inter

### README styling
- Używaj emoji sparingly: 🔒 🛡️ ⚡ ✓ ✗
- Tabele z kolorami severity (via HTML w markdown)
- Code blocks z syntax highlighting

---

## 10. Tone of Voice (w kontekście wizualnym)

- **Minimalistyczny** — mniej elementów, więcej whitespace
- **Techniczny** — nie corporate, nie "startup-owy"
- **Trustworthy** — ciemne kolory, stabilne proporcje
- **Developer-first** — CLI-centric, monospace, terminale

---

## 11. Indeks assetów

Kompletna lista wszystkich plików designowych w `design/`:

### Logo
| Plik | Rozmiar | Opis |
|------|---------|------|
| `logo-icon.svg` | 128×128 | Ikona (shield + scanner), do użytku jako favicon, avatar |
| `logo-full.svg` | 420×128 | Pełne logo z tekstem "MCP Audit" |
| `logo-mono-white.svg` | 420×128 | Monochromatyczne białe — na ciemne tła |
| `logo-mono-dark.svg` | 420×128 | Monochromatyczne ciemne — na jasne tła |
| `color-palette.svg` | 800×600 | Wizualna referencja palety kolorów |

### Badges (`design/badges/`)
| Plik | Status | Kolor prawej strony |
|------|--------|---------------------|
| `badge-passed.svg` | passed | `#3FB950` (zielony) |
| `badge-failed.svg` | failed | `#F85149` (czerwony) |
| `badge-scanning.svg` | scanning | `#D29922` (żółty) |
| `badge-unknown.svg` | unknown | `#8B949E` (szary) |

### Social Media (`design/social/`)
| Plik | Rozmiar | Platforma |
|------|---------|-----------|
| `twitter-banner.svg` | 1500×500 | Twitter / X header |
| `github-social.svg` | 1280×640 | GitHub social preview (og:image dla repo) |
| `og-image.svg` | 1200×630 | OpenGraph image (strona, blog, linki) |

### Eksport do PNG
Aby wyeksportować SVG do PNG (np. do uploadowania na GitHub):
```bash
# Wymaga Inkscape lub rsvg-convert
rsvg-convert -w 1280 -h 640 design/social/github-social.svg -o github-social.png
rsvg-convert -w 1500 -h 500 design/social/twitter-banner.svg -o twitter-banner.png
rsvg-convert -w 1200 -h 630 design/social/og-image.svg -o og-image.png
rsvg-convert -w 128 -h 128 design/logo-icon.svg -o favicon.png
```

---

*Ostatnia aktualizacja: 2026-03-29*
*Wersja: 1.1*
