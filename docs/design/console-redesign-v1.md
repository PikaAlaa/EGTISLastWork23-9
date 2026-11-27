# ETIS console redesign v1

Status: **step 1, preview only. Waiting for owner review.** The live console pages still use
`src/theme/theme.ts` and look the same as before. No backend code, API contract or response shape
changes.

- Preview route: `/design-preview` (`npm run dev`, or `npm run build` then `npx vite preview`).
  You can set these query parameters for review: `?theme=light|dark`, `?lang=ar|en`, `?motion=reduced`.
- Screenshots: `etis-frontend/design-preview/screenshots/`
  (`light-en.png`, `dark-en.png`, `light-ar-rtl.png`, `mobile-390-ar.png`, `mobile-390-en-dark.png`).
- Code added in step 1: `src/theme/tokens.ts`, `src/theme/consoleTheme.ts`, `src/design/motion.css`,
  `src/components/EtisBot.tsx`, `src/components/botState.ts`, `src/components/ScanSurface.tsx`,
  `src/pages/DesignPreview.tsx` and `src/Root.tsx` (route switch). The preview is lazy loaded, so the
  live console bundle doesn't include it. New strings are under `mascot.*` and `designPreview.*` in
  both `ar.json` and `en.json`.

## 1. Direction

The console should feel calm, modern, simple and professional, like a tool for security work.
It avoids hacker clichés: no green-on-black, no falling code, no glitch or matrix effects. The base
is deep navy and slate with one teal accent. Verdict colours appear only where they carry meaning.

## 2. Palette

Each text pair below was measured with the WCAG 2.x relative-luminance formula. All pairs meet AA
(4.5:1 or higher).

### Light theme

| Token | Hex | Use | Contrast |
|---|---|---|---|
| bg | `#F4F6F9` | page background | text 15.96:1 |
| surface | `#FFFFFF` | cards | text-muted 7.03:1 |
| surface2 | `#EEF2F6` | raised / hover surfaces | |
| border | `#D8E0EA` | outlines, dividers | |
| text | `#0F1B2D` | primary text | |
| textMuted | `#4A5A70` | secondary text | 6.49:1 on bg |
| navy | `#14304F` | app bar | white on navy 13.41:1 |
| accent (teal) | `#0F766E` | primary actions, focus, scanning | 5.47:1 on white; white on teal 5.47:1 |
| accentOnNavy | `#5EEAD4` | active-tab indicator on the navy bar | |
| accentSoft | `#E3F3F1` | scanning tint, icon tiles | |
| LOW text / graphic / tint | `#1D7357` / `#2A8C6A` / `#E7F4EF` | calm teal-green | 5.77:1 on white, 5.10:1 on tint |
| MEDIUM text / graphic / tint | `#8F5500` / `#C98A1B` / `#FBF1E0` | amber | 6.06:1 on white, 5.41:1 on tint |
| HIGH text / graphic / tint | `#A93A3A` / `#B9494A` / `#FAECEC` | muted red | 6.26:1 on white, 5.45:1 on tint |

### Dark theme

| Token | Hex | Contrast |
|---|---|---|
| bg | `#0B1424` | text `#E6EDF5` 15.61:1 |
| surface | `#111C2E` | text-muted `#A3B3C7` 8.00:1 |
| surface2 | `#17253A` | text-muted 7.22:1 |
| border | `#24364F` | |
| navy (app bar) | `#0E1A2B` | |
| accent (teal) | `#4CC9B8` | 8.42:1 on surface; bg-coloured text on teal 9.08:1 |
| accentSoft | `#13302F` | |
| LOW text / graphic / tint | `#5CCB9F` / `#4DB98E` / `#13312C` | 8.54:1 on surface, 6.98:1 on tint |
| MEDIUM text / graphic / tint | `#E9B45A` / `#E0A443` / `#30291A` | 9.06:1 on surface, 7.64:1 on tint |
| HIGH text / graphic / tint | `#F08A84` / `#E06F6A` / `#33202A` | 7.06:1 on surface, 6.28:1 on tint |

Rules:

- Verdict colours appear only on verdict chips, verdict cards, scan results and the mascot's
  result states. They are never used for decoration.
- Use the "text" values for text and the "graphic" values only for non-text shapes, such as the
  mascot body and result rings.
- A verdict is never shown by colour alone. Every verdict also has its label (`verdict.*`) and an
  icon (GppGood, GppMaybe or GppBad).
- INCOMPLETE stays a neutral slate: `#52606F` in light, `#94A3B8` in dark.

## 3. Typography

- Cairo covers Arabic and Latin in one family, so the text does not swap fonts when the language
  changes. IBM Plex Mono is for scores, hashes, timestamps, technique IDs and URLs, which are
  always shown as `dir="ltr"` inert text. Both fonts are already loaded in `index.css`.
- Type scale in px: caption 12, small 13, body 15, lead 18, h3 22, h2 28, h1 34. Body line height
  is 1.65 so Arabic text has room to breathe. Headings use weights 600–700.
- Buttons and tabs use sentence case (no uppercase transform).

## 4. Spacing and shape

- 4 px base. The console theme sets `spacing(1)` to 4 px. The scale is 4, 8, 12, 16, 24, 32, 48, 64.
- Radii are 8 for buttons and inputs, 12 for cards and scan surfaces, and 16 for the mascot tip
  and verdict cards. Chips are fully rounded.
- Card padding is 16–20 px. Sections are 48 px apart. Page gutter is 16 px at mobile widths and
  24 px from 600 px up.
- Elevation is flat: 1 px outlines, with a soft shadow only on hover (`.etis-lift`).

## 5. Motion

| Token | Duration | Use |
|---|---|---|
| fast | 150 ms | hover, press, focus |
| base | 220 ms | card and state changes, mascot face swap, tip fade |
| slow | 300 ms | page enter, verdict colour settle, theme change |
| scanCycle | 2400 ms | one scan sweep (line or radar), mascot eye travel |

- Easing: standard `cubic-bezier(0.2, 0, 0, 1)` and exit `cubic-bezier(0.4, 0, 1, 1)`.
- Pages fade in and rise 6 px (`.etis-page-in`). Cards lift 2 px on hover.
- Nothing flashes or glitches. No looping animation runs unless a scan is in progress or the
  mascot is idling.
- **Reduced motion.** When `prefers-reduced-motion: reduce` is set, or an ancestor has
  `data-motion="reduced"` (the preview switch), the sweeps, float, blink, eye tracking, hop and
  shake all stop. Scanning becomes a slow opacity pulse of the tint, and state changes become plain
  fades. The MUI theme also caps transitions at 150 ms in that mode.

## 6. ETIS bot (mascot)

The ETIS bot is an original character and the console's brand mark. It is **not** a chatbot: it
has no text input, no AI and no generated messages. It only mirrors scan state and can show one
fixed tip per state from `mascot.tips.*`.

**Look.** A rounded shield body with a dark navy visor for a face and two soft pale-teal eyes. A
single antenna ends in a "network node" dot, and a small lock sits on the chest. A faint highlight
on the upper shoulder and a soft ground shadow finish it. It is one inline SVG (viewBox 120×140)
styled entirely with CSS custom properties, so it themes automatically and needs no assets. The
shield, lock and node are the security cues. It does not copy any existing mascot or brand
character.

| State | Body colour | Face | Motion |
|---|---|---|---|
| idle | teal accent | oval eyes, small smile | gentle 4 s float, slow blink every ~5.5 s |
| scanning | teal accent | eyes, flat mouth | eyes travel up and down in sync with the 2.4 s scan line; antenna node pulses |
| safe (LOW) | LOW green | happy arc eyes, wide smile, cheeks | one small hop, then float |
| warning (MEDIUM) | amber | raised brows, wide round eyes, flat mouth | antenna node pulses 3 times |
| danger (HIGH) | muted red | worried slanted brows, small eyes, frown | one short shake, then still |

- The body and antenna colours transition over 300 ms, and the face swaps with a 220 ms fade.
- Accessibility: the SVG has `role="img"` and a state label (`mascot.state.*`). The small app-bar
  copy is decorative (`aria-hidden`). Tips render as `role="note"`.
- `botStateFor(status)` maps `idle | scanning | LOW | MEDIUM | HIGH` to a mascot state.

## 7. Scan animation

`ScanSurface` wraps the item being scanned and takes `status`: `idle`, `scanning`, `LOW`, `MEDIUM`
or `HIGH`.

- **Line variant** (message, URL, file). While scanning, the frame turns teal with a soft teal
  tint, and a 2 px teal "shield scan line" with a faint glow band sweeps top to bottom and back
  every 2.4 s. It is direction-neutral, so it behaves the same in RTL.
- **Radar variant** (network imports). A 56 px radar disc with faint rings replaces the icon tile,
  and a teal conic sweep rotates once every 2.4 s.
- **Result arrives.** The sweep fades out over 220 ms. The border, tint and inline-start edge bar
  move to the verdict colour over 300 ms, and one soft ring pulse (700 ms) marks the settle. The
  status chip changes from "Scanning…" to the verdict label. The status sits in
  `role="status" aria-live="polite"`, and the surface sets `aria-busy` while scanning.
- Content stays inert text, so URLs are never links.
- File and network scans are started by local commands, not from the console. In the console the
  same surface animates while a scan or import detail is loading, then settles into its verdict.

## 8. App shell (proposed, shown in the preview header)

- A navy app bar holding the mascot mark, the "ETIS" title and the subtitle, with the theme toggle
  (moon/sun) and the language toggle at the inline end.
- Navigation keeps the existing eight tabs and labels, now with icons from `@mui/icons-material`:
  Radar (live analysis), DynamicFeed (threat feed), Insights (statistics), Report (incidents),
  Fingerprint (file scans), Lan (network), ManageSearch (indicators) and AccountTree (ATT&CK). The
  tabs scroll horizontally on narrow screens, and the active tab has a 3 px teal indicator.
- The theme follows the OS preference on first visit. A toggle overrides it, and the choice is
  remembered in `localStorage` (step 2).

## 9. Pages that change (after approval)

Step 2 is split into three commits:

1. **Theme tokens and app shell.** `App.tsx` switches from `theme.ts` to `consoleTheme.ts` with
   light/dark mode, the shell from §8, and page fade transitions. `verdictPalette.ts` is rebuilt
   from the tokens. `index.css` gets the motion CSS.
2. **Scan pages.** `ScanPage` (the message/URL form gets `ScanSurface` plus the mascot beside the
   result), `VerdictCard` and `EngineBreakdownCard` (verdict tint and settle), `FileScansPage`
   (line scan on the detail while it loads) and `NetworkWindowsPage` (radar while an import detail
   loads).
3. **Other pages.** `ThreatFeedPage`, `StatsPage` (stat cards as in the preview), `IncidentsPage`,
   `IndicatorsPage`, `AttackPage` and `SocChips` get spacing, card and table restyling only, with
   no data or behaviour changes.

No new dependency is needed. Everything uses MUI, `@mui/icons-material`, CSS and inline SVG.

## 10. Content rules kept

- The preview uses obviously illustrative sample values and reserved `example.com` names. The
  sample message is in English in both locales and is labelled "Illustrative sample, not real data
  or a real SMS". No generated or translated text is presented as real Egyptian SMS.
- Nothing in the preview fetches a URL or sends anything to an external service. The only network
  requests are the existing Google Fonts stylesheet and the local bundle.
