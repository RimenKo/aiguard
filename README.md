# aiguard

**Защита от утечек секретов через AI-инструменты** — Claude Code, Cursor, Copilot.

AI-ассистенты пишут код быстро — и в 2 раза чаще случайно включают секреты в публичные файлы.  
Папки `.claude/` и `.cursor/` содержат API-ключи, токены сессий и строки подключения к базам.  
Стандартные сканеры (GitGuardian, gitleaks) их не знают.

`aiguard` знает.

---

## Что ловит

- Папку `.claude/` с `settings.local.json` (хранит API-ключи Claude Code)
- Папку `.cursor/` с конфигурацией и токенами
- Ключи Anthropic, OpenAI, AWS, GitHub, Google, Stripe в любых файлах
- Приватные SSH-ключи
- Строки подключения к базам данных
- Отсутствие `.npmignore` с нужными исключениями

---

## Установка

```bash
npm install -g aiguard
```

Или без установки:

```bash
npx aiguard
```

---

## Использование

**Проверить проект перед публикацией:**
```bash
aiguard              # текущая папка
aiguard ./my-project # конкретная папка
```

**Автоматически блокировать `npm publish`** — добавь в `package.json`:
```json
{
  "scripts": {
    "prepublishOnly": "aiguard"
  }
}
```

**Защита в Claude Code** (блокирует запись секретов ИИ-агентом) — скопируй хук:
```bash
cp node_modules/aiguard/claude-hook/settings.json .claude/settings.json
```

---

## Почему это важно

- Исследование Lakera (апрель 2026): в **30 npm-пакетах** найдены живые ключи из-за папки `.claude/`
- **2.4%** репозиториев с AI-инструментами содержат секреты в истории коммитов
- AI-код сливает секреты в **2 раза чаще** обычного (данные GitGuardian 2026)
- Cursor хранит ключи в незашифрованной базе — патча нет

---

## Рекомендуемый `.npmignore`

```
.claude
.cursor
.continue
.aider
.env
.env.*
*.local
```

---

## Лицензия

MIT
