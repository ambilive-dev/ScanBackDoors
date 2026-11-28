# RECON — что где лежит (снимок для рефакторинга по ТЗ v2)

Разведка Спринта 0. Снимок: **v3.3.1, коммит `6bbdf9d`, 2026-11-28**. Номера строк
указаны на этот снимок — после изменений сверять по именам, а не по строкам.
Всё, что не увидено в коде, помечено «не подтверждено» и унесено в
[OPEN_QUESTIONS.md](OPEN_QUESTIONS.md).

Общий контур: три исполняемых инструмента в `src/` (`scan_backdoors.py` 1932 стр.,
`clean_malware.py` 783 стр., `joomla_baseline.py` 440 стр., GUI
`scan_backdoors_gui.py` ~3900 стр.) и тесты в `tests/` (harness + fixtures).
Единственный внешний контракт запуска — CLI и коды возврата; GUI общается с ядром
только subprocess'ом сканера/чистильщика и своими HTTP-эндпоинтами (`/api/...`,
заголовок `X-Requested-With: scan-backdoors-gui`, bind 127.0.0.1).

---

## 1. Ядро сканера (`src/scan_backdoors.py`)

### 1.1 Пороги, веса, капы (блок констант, стр. 78–144)

| Имя | Значение |
|---|---|
| `SEV_CRIT/SEV_OBF/SEV_WARN` (82–84) | строки `[CRITICAL]` `[OBFUSCATED]` `[WARNING]` |
| `DEFAULT_WEIGHT` (87) | CRIT 10, OBF 3, WARN 1 |
| `SCORE_CAP` (88) | CRIT 200, OBF 45, WARN 9 |
| `HIGH_SCORE` / `MEDIUM_SCORE` (89–90) | 25 / 10 |
| `PATTERN_CAP` (93) | 100 совпадений одной сигнатуры в файле |
| `LONG_LINE` (94), `ENTROPY_LIMIT` (95) | 2000; 5.7 (в `blob_hits` ещё 5.6, стр. 798) |
| `DEFAULT_MAX_SIZE` (92) | **объявлена, не используется** — реальный лимит `--max-size` (МБ, float, дефолт 5; стр. 1649) |

Классификаторы путей/имён: `PHP_EXT/HTML_EXT/TEXT_EXT/INI_EXT/MEDIA_EXT`
(98–106), `STRICT_DIRS={"images","tmp"}` (130), `SOFT_DIRS={"cache","logs"}` (131),
`CORE_PREFIXES` (133), `MALWARE_NAMES` (117), `SHELL_NAMES` (122),
`SHELL_NAME_PREFIXES` (127), `WP_CORE_PREFIXES` (175), `WP_SHELL_NAME_EXEMPT` (178),
регулярки имён `BACKUP_RE/DOUBLE_RE/HTACCESS_NAME_RE/IMG_DOUBLE_RE` (108–114).
**Списка «расширений для сканирования по умолчанию» нет: обход берёт все файлы**,
классификация (`classify`, 365–399) определяет проверки; `--exclude-dir` по умолчанию
пуст (1660). Сигнатуры объявляются вызовами `S(...)` в стр. 181–311 (веса там же);
user-signatures подключаются отдельно.

### 1.2 Скоринг и вердикт

- `compute_score` (932–947): CRIT суммируются полностью; повторные OBF/WARN —
  не более 2× веса одной сигнатуры; кап по `SCORE_CAP`; без CRIT итог ≤ 24.
- `verdict_of` (950–955): ≥25 HIGH, ≥10 MEDIUM, иначе LOW. Уровень в отчёте —
  вердикт; severity-теги — у отдельного хита.
- Коды возврата main: 1 — ошибки запуска (папка, `--since`, whitelist,
  user-signatures, baseline-dir; стр. 1695–1742); 2 — есть `[CRITICAL]`-хит (1926–1927);
  3 — `--strict` и были ошибки чтения (1928). `sys.exit(main())` 1932.

### 1.3 Приоритет решений на файл (`scan_file`, цикл 992–1101)

1. `skip_paths`: собственные отчёты и файл скрипта исключены из обхода (992–994, 1751–1753);
2. `--exclude-ext` (1003); `--since` (1018);
3. **whitelist по пути** (1021–1024): без `--audit-whitelisted` файл НЕ читается
   (`"whitelisted_path"`), с флагом — ищутся только CRIT;
4. **whitelist по SHA-256** (1041–1045): хеш считается лениво (нужен для whitelist
   или baseline);
5. **baseline** (1047–1057): sha256 совпал → `"core_ok"`, контент-проверки пропускаются;
   иначе «differs from the clean Joomla file» (вес 10), «extra Composer package» (2),
   «not part of clean Joomla» (10);
6. эвристики/сигнатуры (1060–1094), итог `make_result` (1101).

Приоритет ровно тот, что требует ТЗ P3: path-whitelist → hash-whitelist → baseline → движки.
Whitelist-файл: `load_whitelist` (1482–1503) — `#`-комментарии, хеш = ровно 64 hex,
иначе путь/папка (`/` на конце)/маска (маска не пересекает `/`, `path_whitelisted` 958–966).
Поставка: `data/whitelist-known-clean.txt` (~977 КБ дайджестов) — **только через
`--whitelist`**, автоматически не грузится. Генератор: `tools/build_allowlist.py`.

### 1.4 Baseline

`--baseline-dir` (1667) → проверка папки+`index.php` (1739–1744) → `build_baseline`
(1506–1543): sha256 каждого `.php` чистого дерева; быстрый путь — манифест
`<dirname>/<basename>.baseline.json` рядом с деревом (пишет `joomla_baseline.py`),
файлы вне манифеста хешируются. `baseline_pkgs` (1760) — исключение «extra Composer
package» (1054–1055).

### 1.5 Форматы отчётов

- CSV (1141–1149): `Score, Verdict, Severity, File, Line, Signature, Snippet, Size,
  Modified, Delete, SHA-256`; UTF-8-BOM; `csv_safe` (1136–1138) экранирует leading
  `= + - @` — защита от формульных инъекций (CWE-1236) уже есть; колонку `Delete`
  и AI-колонки позже переписывает GUI (§4).
- JSON (1152–1160): `{version, stats, files:[{path, score, verdict, size, modified,
  mode, sha256, counts, hidden_hits, hits:[{severity, line, signature, snippet}]}]}`.
- SARIF 2.1.0 (1170–1206): правило=label, level по `SEV_SARIF` (86), uri — относительный
  путь, `%SRCROOT%` = сканируемая папка.
- XLSX (1209–1337): zip of XML, собран вручную, `XLSX_MAX_ROWS` 1307.
- Блок `STATISTICS` печатается 1872–1892; словарь `stats` (1849–1861) — ключи
  `Files visited/scanned/flagged, HIGH/MEDIUM/LOW, [CRITICAL/OBFUSCATED/WARNING] hits,
  Identical to clean Joomla (skipped), Whitelisted, Whitelisted by path (content NOT
  scanned), Skipped (too big), Skipped (older than --since), Read errors,
  Unreadable (Windows permissions), Time, s, Same-name nested folders` — это и есть
  существующий «учёт покрытия» (P1 ТЗ частично уже выполнен: пропуски видны).
- `--progress-lines`/`@@STATS`-маркеры (1924) — машинный протокол для GUI.

### 1.6 Запись на диск: ВСЕ пути

| Инструмент | Что пишет | Куда |
|---|---|---|
| сканер | CSV/XLSX/JSON/SARIF | только пользовательские пути (`--csv` дефолт `report-data.csv` от **cwd запуска**, остальные без дефолта) |
| сканер | self-test | временные `<tmp>/sbd-fixtures/sbd-selftest-*`, удаляются (1602–1640) |
| cleaner `--apply` | карантин | **по умолчанию `<родитель сайта>/_quarantine_<имя сайта>/<stamp>`** (572–579), если родитель недоступен — cwd; `--quarantine-dir` (494); проверка «карантин не внутри сайта» при apply (585–599) |
| cleaner | файлы `.quarantine/.orig/.modified` — рядом с оригиналом **внутри сайта** (304/326/343); правки на месте (329–350, chmod 361, откат 367); удаление `os.unlink` (309, 318) | внутри сайта — только когда пользователь явно дал `--apply` |
| cleaner | манифест карантина | `<qdir>/manifest.json` (740–741); отчёт `--report` дефолт `cleanup-report.csv` (497, 748) |
| cleaner `--restore` | восстановление | только внутрь сайта из манифеста, с проверкой sha256 (384–427) |
| baseline | кэш | `<--out дефолт joomla-baselines от cwd>/<Joomla_ver>/` + `<...>.baseline.json`; `.part`, `.tmp-<ver>`, атомарные `os.replace` (97–136, 310–391) |
| GUI | настройки | `~/.scan_backdoors_gui.json` (`CONFIG_PATH` 45; запись `update_settings` 575) |
| GUI | библиотека AI-подписей | `~/.scan_backdoors_user_signatures.json` (`USER_SIGS_PATH` 49–50; атомарно 1732–1734) |
| GUI | whitelist append | путь из настройки `whitelist_path`; **если не задан — `<папка сканера>/whitelist.txt`** (942–944) |
| GUI | CSV-отчёт | три атомарных переписывания колонок `Delete` / `AI Verdict/AI Comment/AI Handled` (902–931, 1521–1560, 1749–1781) |
| GUI | карантины по одному | `<родитель сайта>/_quarantine_<сайт>/<timestamp>` + `manifest.txt` (857–866) |
| GUI | Fetch baseline | запускает `joomla_baseline.py --out <папка файла сканера>/joomla-baselines` (1173–1178) |
| GUI | прочее | в сканируемый сайт пишет только при явных действиях пользователя (quarantine/delete/mass cleanup) |

**Вывод для ТЗ §2.3:** сканер в сканируемый сайт не пишет вообще; карантин по
умолчанию лежит ВНЕ сайта (в его родителе), правки внутри сайта — только явный
`--apply` чистильщика. Два места «рядом со сканером» (этно-каталог `whitelist.txt`
по умолчанию и `joomla-baselines/` из Fetch baseline) — кандидаты на перенос в
каталог данных; зафиксировано в OPEN_QUESTIONS.

---

## 2. GUI (`src/scan_backdoors_gui.py`)

- Настройки: `DEFAULTS` (стр. ~60–75; ключи `scanner_path, site_dir, baseline_dir,
  whitelist_path, csv_path, xlsx_path, json_path, max_size, max_matches, since,
  exclude_ext, exclude_dir, workers, flags..., clean_core, clean_fm, clean_permanent,
  ai_enabled, ai_base_url, ai_model, ...`); `--csv/xlsx/json` сканеру резолвятся
  **относительно папки сканера** (`abs_from_setting` 593–597).
- Модель задач: `_start_job/_run_job/_job_finished` + опрос `/api/state` браузером;
  kinds: `scan`, `clean-plan`, `clean-apply`, `baseline`. Никакого SSE — подтверждено.
- Эндпоинты (префикс `/api/`): ping, settings, state, preflight, scan/start, job/stop,
  findings, finding, files/{preview,reveal,do,paths,whitelist}, report/{open,folder},
  clean/{plan,apply,cancel}, baseline/{detect,fetch}, ai/{review,candidates,signatures/*},
  fs, shutdown. CSRF-заголовок обязателен на POST; bind 127.0.0.1.

## 3. Фикстуры и харнесс (`tests/`)

- `fixtures_sites.py`: `CLEAN` (444–471, инлайн-тексты + 1px GIF/PNG) — 28 файлов,
  ноль находок; `PLANTED` (483–560) — 11 образцов из `tests/payloads/*.b64`
  (`unseal` из `seal_payloads.py`), каждый с ожидаемыми `signatures/verdict`;
  запись LF (`io.open(..., newline="\n")`) → sha256/размер стабильны между платформами;
  `build(name, planted, extra, binaries)` 610–629, `fixtures_root()` =
  `SBD_FIXTURE_ROOT` или `<tmp>/sbd-fixtures`; `wait_readables` — учёт антивируса.
- `harness.py`: `run` (subprocess src-скрипта, cwd=src), `scan` (детерминированный
  прогон workers=1), `Gui` (приватный HOME/USERPROFILE/AppData — реальный конфиг
  разработчика неприкосновенен), `tree_hashes`, `workdir` (внутри fixtures_root).
- CI (`.github/workflows/ci.yml`): push main + PR; `ubuntu-24.04 + windows-latest`,
  Python **3.8 / 3.11 / 3.13** (3.6 рантаймом НЕ тестируется; обещание 3.6 держит
  статический `test_compat.py` (OLDEST=(3,6)) и fallback-механизмы вроде
  `scan_batch_cfg`). Запуск: `python -m unittest discover -s tests -v`.

## 4. Страховочная сетка Спринта 0 (что добавлено этим ТЗ-спринтом)

- `tests/test_golden_scan.py` + `tests/golden/planted_scan.json` — characterization
  golden: набор находок (path/score/verdict/size/sha256/hits) на planted-фикстуре,
  коды возврата, чистый корпус = ноль находок, скан не изменяет дерево сайта.
  Перезапись golden — только осознанно: `python tools/record_golden.py` (git diff
  перезаписи = протокол изменения детекции).
- `tools/fp_measure.py` + `tests/golden/fp_baseline_synthetic.json` — FP-бюджет
  синтетического чистого корпуса (28 файлов, 0 находок). Корпус реальных CMS —
  OPEN_QUESTIONS (лицензии/целостность по ТЗ §5.1 п.4).

## 5. Расхождения с ТЗ v2 (факт против предположений ТЗ)

| ТЗ говорит | Реальность |
|---|---|
| коды возврата «0/1/2» | есть и **3** (`--strict` + ошибки чтения, стр. 1928) |
| «капы 200/45/9, веса 10/3/1, HIGH 25 / MEDIUM 10, уровни CRITICAL/OBFUSCATED/WARNING» | подтверждено ровно так |
| GUI-порт «8765» | дефолт есть (`DEFAULT_PORT`), но стартовый диапазон фолбэка 8765–8864 (v3.3.1); в ТЗ не фиксировать |
| структура §4.1 (скрипты в корне) | скрипты в `src/`, фикстуры payloads — base64 в `tests/payloads/` |
| Python 3.6 в CI | 3.6 обещана README/докстрингами, но CI-матрица 3.8+; 3.6-совместимость статическая |
| «учёт покрытия отсутствует» | частично есть: stats/STATISTICS считает too big / read errors / unreadable / whitelisted; НО таймаутов движков нет (движков пока нет) |
| CSV-инъекции (§10) | уже защищены `csv_safe`; XLSX-путь экранирует управляющие символы (`x_esc`) |
| GUI «клиент не передаёт пути» | в `/api/settings` клиент передаёт пути (site_dir, whitelist...) — это доверенный локальный оператор; но загрузка файлов (Fetch baseline) пути от клиента НЕ принимает — путь `--out` серверная константа ✓ |
