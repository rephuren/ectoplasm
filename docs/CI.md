# Подключение к GitHub Actions

`action.yml` в корне репозитория запускает `ectoplasm trace` и пишет SARIF. Загрузка SARIF на вкладку Security делается стандартным шагом `github/codeql-action/upload-sarif`.

```yaml
name: agent-session-audit
on: [pull_request]
permissions:
  contents: read
  security-events: write
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: rephuren/ectoplasm@main        # репозиторий должен быть доступен этому workflow
        with:
          sessions: agent-sessions/session.jsonl
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: ectoplasm.sarif
```

Что важно знать:

- Журнал сессии агента нужно где-то сохранить: ectoplasm разбирает файл, а не запускает агента. Журналы содержат личное (команды, пути, куски файлов), не кладите их в публичный репозиторий.
- Шаг не роняет сборку: находки смотрите на вкладке Security. Хотите блокировать, уберите `|| true` в `action.yml` и используйте код возврата 1.
- **Этот workflow я не запускал в настоящем GitHub Actions**, проверены только команда `ectoplasm trace --sarif` и разбор SARIF в тестах.
