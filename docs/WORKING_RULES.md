# Working Rules / Рабочие правила

[English](#english) | [Русский](#русский)

## English

This file is the single source of working rules for the project. If a rule here
contradicts an oral habit or an old note, this file is what to trust.

### 15 postulates

1. **Documents are the source of truth.** First read the documents, then write
   the code.
2. **Do not confuse execution with improvisation.** If the documents say one
   thing, you cannot silently do another.
3. **Maximum, not minimum.** Design straight away for a million active users,
   and as if reliability were a matter of life and death.
4. **Privacy above all else.** Convenience, speed and simplicity must not break
   privacy.
5. **Speed must be lightning-fast.** Protection must not turn the product into
   something slow and heavy.
6. **Our code — only in Rust.** Exceptions are allowed only for external
   tooling, bindings and already-approved boundaries.
7. **After each iteration — a history entry and an update to the documents.**
   If you changed behaviour — update the related files immediately.
8. **Documents are updated after every change.** Code and description must not
   drift apart.
9. **Before losing context — write a history entry, hand off the state and
   leave instructions to re-read the documents.**
10. **Large features start with a roadmap.** You cannot start large work
    without a plan.
11. **Public documentation — English-first with a Russian section at the end**,
    plain language. Internal working rules (`WORKING_RULES.md`, audit closure
    snapshots, inverse-layout legacy files) may be Russian-only by exception.
    Do not hide meaning behind unnecessary foreign words.
12. **After context compaction — first re-read the documents, then continue
    work.**
13. **Execute autonomously within the goal.** Do not stop halfway if the goal
    is clear and the action is safe.
14. **Bugs and TODO markers are resolved immediately and recorded.** You may
    not leave a known hole as if it were not there.
15. **Code is always at the level of a strong senior engineer and researcher.**
    Comments on public interfaces — in Russian and English; checks — strict,
    without silent bypasses. Cross-check versions and documentation against
    fresh sources.

### How to apply

- If a test passes only because it checks a stub, that does not count as a
  real check.
- If a protection is claimed in the documents, the code must either perform it
  or honestly refuse to work.
- If the implementation is not ready yet, the public interface must not look
  like a finished production path.
- If a discrepancy is found between document, code and test, first fix the
  source of truth, then the code, then the test.

---

## Русский

Этот файл — единый источник рабочих правил проекта. Если правило здесь
противоречит устной привычке или старой заметке, верить нужно этому файлу.

### 15 постулатов

1. **Документы — источник правды.** Сначала читаем документы, потом пишем код.
2. **Не путать исполнение и отсебятину.** Если в документах сказано одно, нельзя
   молча делать другое.
3. **Максимум, не минимум.** Проектировать сразу под миллион активных
   пользователей и так, будто от надёжности зависит жизнь.
4. **Приватность превыше всего.** Удобство, скорость и простота не могут ломать
   приватность.
5. **Скорость должна быть молниеносной.** Защита не должна превращать продукт в
   медленный и тяжёлый.
6. **Наш код — только на Расте.** Исключения допустимы только для внешних
   инструментов, привязок и уже утверждённых границ.
7. **После каждой итерации — запись в историю и обновление документов.** Изменил
   поведение — сразу обнови связанные файлы.
8. **Документы обновляются после каждого изменения.** Код и описание не должны
   расходиться.
9. **Перед потерей контекста — запись в историю, передача состояния и инструкция
   перечитать документы.**
10. **Крупные возможности начинаются с дорожной карты.** Без плана нельзя
    начинать большую работу.
11. **Публичная документация — EN-first с Russian-секцией в конце**, простым
    языком. Внутренние рабочие правила (`WORKING_RULES.md`, closure-снимки
    audits, inverse-layout legacy файлы) могут быть RU-only по исключению. Не
    прятать смысл за лишними иностранными словами.
12. **После сжатия контекста сначала перечитать документы, потом продолжать
    работу.**
13. **Исполнять автономно в рамках цели.** Не останавливаться на полпути, если
    цель ясна и действие безопасно.
14. **Баги и пометки к доработке решаются сразу и фиксируются.** Нельзя оставлять
    известную дыру как будто её нет.
15. **Код всегда уровня сильного старшего инженера и исследователя.** Комментарии
    к открытым интерфейсам — на русском и английском; проверки — строгие, без
    тихих обходных путей. Версии и документацию сверять по свежим источникам.

### Как применять

- Если тест проходит только потому, что проверяет заглушку, это не считается
  настоящей проверкой.
- Если защита заявлена в документах, код должен либо выполнять её, либо честно
  отказываться работать.
- Если реализация ещё не готова, публичный интерфейс не должен выглядеть как
  готовый боевой путь.
- Если найдено расхождение между документом, кодом и тестом, сначала исправить
  источник правды, потом код, потом тест.
