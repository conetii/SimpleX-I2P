# SimpleX-I2P: Состояние проекта

## Что сделано

### SMP сервер (работает) ✅
- SQLCipher хранилище: очереди + сообщения, полный CRUD
- SMP протокол: парсер/сериализатор 16384-байтных блоков, все 8 команд (NEW, KEY, SEND, SUB, GET, ACK, OFF, DEL)
- TLS 1.3 сервер: thread-per-connection, self-signed cert generation (Ed25519)
- SMP handshake: version negotiation (v6-17), ServerHello/ClientHello, tls-unique session binding
- Subscription push: при SEND проверяет активных подписчиков и пушит MSG
- Unit-тесты протокола: парсинг всех команд + сериализация ответов

### Docker deployment (работает) ✅
- docker-compose.yml: i2pd + smp-server, оба с `network_mode: host`
- Dockerfile: multi-stage build (debian:bookworm)
- .dockerignore: исключает build/ чтобы не конфликтовал CMakeCache
- i2pd конфиг: порт 4568, web console на 7072, SSU2+NTCP2
- tunnels.conf: server tunnel → 127.0.0.1:5223, 1 хоп, 4 туннеля
- ulimits: nofile 16384 (предотвращает exhaustion file descriptors)

### Скрипты (работают) ✅
- setup.sh: генерирует .env, запускает docker compose
- show-address.sh: берёт b32 адрес из i2pd web console, fingerprint из TLS cert

## Что работает ✅

### I2P подключение (РАБОТАЕТ!)
- **LeaseSet опубликован и стабилен** - LeaseSets: 1
- Tunnel success rate: 52-53% (стабильно)
- Роутеры: 5700+, Floodfills: 1800+
- Туннели: 12 активных (established)
- Адрес: g5bm3ojgzmfhoze6f3rjjd2ze425ya3jm5lk2wa3rrjsdwfmplxa.b32.i2p

### SMP совместимость с SimpleX клиентом
- Формат адреса: `smp://O4rSxZ_PJdZZWOZhCuwjsKIgBm0GZoBUYZ9KBM6l_bc@g5bm3ojgzmfhoze6f3rjjd2ze425ya3jm5lk2wa3rrjsdwfmplxa.b32.i2p`
- Сервер доступен через I2P
- Готов к тестированию с реальным SimpleX клиентом

## Критическое открытие

### Transit tunnels должны быть отключены
- **С `transittunnels > 0`**: LeaseSet НЕ публикуется даже после 50+ минут
- **С `transittunnels = 0`**: LeaseSet публикуется за 5 минут
- Причина: ограниченные ресурсы VPS, transit tunnels мешают публикации LeaseSet
- Это специфично для данного VPS/провайдера

## Рабочая конфигурация

### i2pd.conf
```ini
bandwidth = 2048

[limits]
transittunnels = 0  # КРИТИЧНО - должно быть 0
openfiles = 0
coresize = 0

[reseed]
verify = false  # провайдер блокирует HTTPS к reseed серверам
threshold = 25
```

### tunnels.conf
```ini
[simplex-smp]
type = server
host = 127.0.0.1
port = 5223
keys = simplex-smp.dat
inbound.length = 1   # НЕ 0, НЕ 2
outbound.length = 1
inbound.quantity = 4  # НЕ 6
outbound.quantity = 4
```

## Что нужно сделать дальше

1. ✅ ~~Деплой на VPS~~ - ГОТОВО
2. ✅ ~~Проверить I2P~~ - РАБОТАЕТ, LeaseSet опубликован
3. **Тест с SimpleX клиентом** - подключиться с телефона через I2P (InviZible Pro)
4. Доработать handshake - если SimpleX клиент не проходит дальше handshake
5. Опционально: libi2pd - встроить i2pd в сервер

## Тестирование с SimpleX клиентом

### На Android (InviZible Pro):
1. Установить InviZible Pro
2. Запустить I2P модуль (НЕ Tor!)
3. Дождаться подключения к сети (10-15 минут)
4. В SimpleX: Settings → Network → SOCKS proxy
   - Host: `127.0.0.1`
   - Port: `4447`
5. Добавить сервер:
   ```
   smp://O4rSxZ_PJdZZWOZhCuwjsKIgBm0GZoBUYZ9KBM6l_bc@g5bm3ojgzmfhoze6f3rjjd2ze425ya3jm5lk2wa3rrjsdwfmplxa.b32.i2p
   ```

## Технические заметки

- SQLCipher: нужен `#define SQLITE_HAS_CODEC` перед `#include <sqlite3.h>`
- i2pd в Docker: datadir = `/home/i2pd/data`, НЕ `/var/lib/i2pd`
- SimpleX fingerprint: base64url (без padding) от SHA256 DER сертификата
- i2pd web console: `/?page=local_destinations` для списка адресов
- Порт 7070 может быть занят системным i2pd - используем 7072
- **Firewall**: порт 4568/udp ДОЛЖЕН быть открыт: `sudo ufw allow 4568/udp`

## Обслуживание

### Если LeaseSet пропал:
1. Проверить tunnel success rate (должен быть >40%)
2. Если rate хороший но нет LeaseSet - пересоздать ключи:
   ```bash
   docker compose exec i2pd rm -f /home/i2pd/data/simplex-smp.dat
   docker compose restart i2pd
   # Подождать 5 минут
   ```
3. Проверить что transittunnels = 0 в конфиге

### Мониторинг:
```bash
# Проверить LeaseSet
curl -s http://localhost:7072/?page=local_destinations

# Проверить rate
curl -s http://localhost:7072/ | grep "Tunnel creation"

# Логи
docker compose logs i2pd -f
```

### НЕ ДЕЛАТЬ:
- ❌ Включать transit tunnels (transittunnels > 0)
- ❌ Использовать 0-hop туннели (нестабильно)
- ❌ Использовать больше 4-5 туннелей (трата ресурсов)
- ❌ Включать SOCKS proxy на сервере (влияет на производительность)

## Уроки

1. **Transit tunnels несовместимы с этим VPS** - должны быть отключены
2. **0-hop туннели не помогают** - 1 hop оптимально
3. **Больше туннелей ≠ лучше** - 4 туннеля оптимально, 6 вызывают проблемы
4. **Пересоздание ключей помогает** - старые ключи могут "застрять"
5. **Нужно терпение** - публикация LeaseSet занимает 5-10 минут
6. **VPS провайдер важен** - adminvps.ru имеет специфичные ограничения
