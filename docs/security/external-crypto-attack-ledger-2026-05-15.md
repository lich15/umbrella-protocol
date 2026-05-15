# Внешний реестр KT split-view атак

Дата: 2026-05-15

## Русский

Этот файл фиксирует внешний ресерч для усиления Umbrella KT против раздвоения
журнала. Вывод один: одиночная валидная подпись головы дерева не доказывает, что
другим клиентам не показали другой корень. Нужны цепочка эпох, проверка
неизменности, свидетели с памятью и обмен публичными наблюдениями.

| Источник | Что взяли | Как закрыто локально |
|---|---|---|
| RFC 9162 Certificate Transparency | signed tree head, inclusion и consistency proof | `KtObservation`, `KtObservationHistory` |
| CONIKS | пользователи и наблюдатели ловят расхождение корней | `EquivocationEvidence` |
| IETF Key Transparency draft | клиент хранит увиденные корни и проверяет движение вперёд | `observation_history_rejects_epoch_regression_and_broken_chain` |
| Trillian | клиент хранит головы дерева и требует продолжения истории | `KtObservationHistory` |
| WhatsApp AKD + Cloudflare Auditor | эпоха связывает previous/current root, аудитор проверяет уникальность | `WitnessSigningLedger` и публичные наблюдения |
| Consistency-or-Die | при недоказанной согласованности клиент останавливается | `KtTrustDecision::NeedsObservation` и `EquivocationDetected` |

## Остаток перед боем

Локально реализовано ядро доказательства и отказа. Живая гарантия требует
настоящих серверов, настоящих независимых свидетелей, публичного канала
наблюдений и клиентского обмена наблюдениями.
