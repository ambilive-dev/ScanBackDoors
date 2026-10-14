# Промпт для ИИ-генератора — логотип ScanBackDoors (вариант 2, blue + white)

**Куда вставлять:** в любой генератор картинок (Midjourney / Flux / Nano Banana / DALL·E / Kandinsky). Промпты на английском — так модель их лучше держит. Палитру и стоп-лист копировать целиком, ничего не выкидывать.
**Формат результата:** только растр PNG. Никаких векторов, SVG, AI, PDF и макетов в Figma.

---

## Палитра — строго эти 5 цветов

| HEX | Роль |
|---|---|
| `#2E7DD1` | основной синий: прицел, галстук, текст на светлом |
| `#1B5A99` | тёмно-синий: объём, тени, акцентный текст |
| `#7FB6EA` | светло-синий: свечение линз, блик прицела, `Scan` на тёмном |
| `#FFFFFF` | белый: текст на тёмном, негативная версия |
| `#0A1420` | почти-чёрный фон, основной текст |

Красного, оранжевого, жёлтого, зелёного — нет вообще.

---

## Промпт 1 — ЭМБЛЕМА (главный запрос, 1:1, 1024×1024)

```
Flat vector logo emblem. Single subject, centered: front-facing bust of a professional man wearing a full-face gas mask, shoulders cropped at the bottom edge. Mask body in matte #0A1420 with clean geometric panels and simple round filters. Two round goggle lenses glowing #7FB6EA, each crossed by one thin horizontal scan line. Suit collar and a single necktie below the mask, tie in #2E7DD1. A thin circular targeting reticle ring surrounds the head, ring in #2E7DD1, with four short tick marks at 12, 3, 6 and 9 o'clock. Solid background #0A1420, generous empty margin, head about 62% of canvas height.

Style: flat vector illustration, bold simplified shapes, crisp edges, high contrast, readable as a silhouette. Only one gradient allowed: the soft glow inside the lenses.

Palette strictly limited to #2E7DD1 #1B5A99 #7FB6EA #FFFFFF #0A1420.

Absolutely no text, no letters, no numbers, no wordmark, no tagline, no ribbon, no shield, no padlock, no key, no skull, no hood, no globe, no flag, no YouTube play button.

The mark must stay recognizable when cropped into a circle and shrunk to 32x32 pixels.
```

## Промпт 2 — ФОН ПОД БАННЕР (16:9, 2048×1152)

Текст в баннере ИИ рисовать не умеет аккуратно — просим только фон и знак, надпись ставим потом отдельно.

```
Wide channel banner background, flat vector style. Dark background #0A1420 with a very subtle radial light in the center and a faint thin grid of #1B5A99 lines at low opacity. Place the same emblem described below on the LEFT third of the canvas, vertically centered, small enough to keep a wide empty area on the right for a headline. Emblem: front-facing bust in a full-face gas mask, matte #0A1420 mask, round goggles glowing #7FB6EA, tie in #2E7DD1, thin circular targeting reticle ring in #2E7DD1 around the head.

Keep every important element inside the central horizontal band of the image; the outer 12% on each side and the top and bottom 30% must stay empty.

Flat vector, minimal, no text, no letters, no numbers, no logo lockup, no border, no watermark. Palette strictly #2E7DD1 #1B5A99 #7FB6EA #FFFFFF #0A1420.
```

## Промпт 3 — УПРОЩЁННАЯ ИКОНКА: тест на 32 px (1:1, 512×512)

Отдельный прогон «плоской упрощённой» версии — она лучше выживает в аватарке и фавиконе.

```
Minimal flat app icon, single glyph-like mark: front-facing gas mask silhouette with two round glowing lenses #7FB6EA and a thin broken circle around it #2E7DD1, on a solid #0A1420 rounded square. Extremely simplified: no shoulders, no tie, no filters, no shading, no thin lines thinner than 3% of canvas width. Two colors only: #2E7DD1 and #7FB6EA on #0A1420. Must be legible at 16x16 pixels. No text, no letters.
```

---

## Негатив-промпт (единый, подставлять ко всем трём)

```
text, letters, words, alphabet, typography, numbers, watermark, signature, 3d render, photorealistic, photo, cinematic, gradient mesh, bevel, emboss, chrome, glossy plastic, drop shadow, lens flare, bloom, noise, grain, texture, sketch, pencil, brush strokes, grunge, distressed, cluttered, tiny details, multiple logos, frame, border, mockup, t-shirt, business card, website screenshot, shield, padlock, key, skull, hood, hacker in hoodie, green matrix code, flag, globe, youtube play button, joomla logo, red, orange, yellow, green, warm colors
```

---

## Что должно получиться на выходе (растр)

1. `emblem_1024.png` — квадрат, тёмный фон, без текста.
2. `emblem_800_transparent.png` — та же эмблема на прозрачности, под аватар YouTube.
3. `icon_512.png` — упрощённая иконка из промпта 3.
4. `banner_bg_2048.png` — фон из промпта 2, без надписей.
5. Ч/б-версии эмблемы: чёрная по белому и белая по чёрному (делается обесцвечиванием, не перегенерацией).

## Чек-лист приёмки (6 пунктов)

- [ ] В кадре нет ни одной буквы и цифры.
- [ ] В палитре нет цветов кроме пяти заявленных (проверить пипеткой).
- [ ] Эмблема узнаётся в круге 32×32 — скриншот в реальном размере, не «на глаз».
- [ ] После обесцвечивания знак не превращается в серое пятно.
- [ ] Нет тонких линий тоньше 3 % ширины кадра — они исчезнут на аватарке.
- [ ] Баннер: всё важное в центральной полосе, по краям пусто.

## Что делать с результатом

Генерировать 6–8 кадров за прогон, отбирать **только по тесту 32 px**, а не по красоте на большом экране. Удалить кадры, где ИИ всё-таки дорисовал текст или play-кнопку, — дорисовкой это не лечится. Вордмарк `ScanBackDoors` набирается отдельно шрифтом (Montserrat ExtraBold / Archivo Black), цветом: `Scan` → `#7FB6EA`, `BackDoors` → `#FFFFFF` на тёмном и `#2E7DD1` / `#1B5A99` на светлом.
