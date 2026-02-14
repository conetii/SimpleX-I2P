# SimpleX-I2P: Состояние проекта

## Что сделано

### SMP сервер (работает)
- SQLCipher хранилище: очереди + сообщения, полный CRUD
- SMP протокол: парсер/сериализатор 16384-байтных блоков, все 8 команд (NEW, KEY, SEND, SUB, GET, ACK, OFF, DEL)
- TLS 1.3 сервер: thread-per-connection, self-signed cert generation (Ed25519)
- SMP handshake: version negotiation (v6-17), ServerHello/ClientHello, tls-unique session binding
- Subscription push: при SEND проверяет активных подп��счиков и пушит MSG
- Unit-тесты протокола: парсинг всех команд + сериализация ответов

### Docker deployment
- docker-compose.yml: i2pd + smp-server, оба с `network_mode: host`
- Dockerfile: multi-stage build (debian:bookworm)
- .dockerignore: исключает build/ чтобы не конфликтовал CMakeCache
- i2pd конфиг: порт 4568, web console на 7072, SSU2+NTCP2
- tunnels.conf: server tunnel → 127.0.0.1:5223, 2 хопа, 5 туннелей

### Скрипты
- setup.sh: генерирует .env, запускает docker compose
- show-address.sh: берёт b32 адрес из i2pd web console, fingerprint из TLS cert

## Что НЕ работает

### I2P подключение
- i2pd не может опубликовать LeaseSet — LeaseSets всегда 0
- Причина: серый IP от провайдера (CGNAT / Symmetric NAT)
- Туннели строятся (5+5 established), но публикация фейли��ся
- Лог: "Publish confirmation was not received in 1800 milliseconds"
- Пробовали: Docker NAT, host network, port forwarding на D-Link, UPnP, 0-hop туннели, отключение NTCP2, IPv6, системный i2pd — ничего не помогло
- Решение: деплой на VPS с белым IP

### SMP совместимость с SimpleX клиентом
- Формат адреса принимается: `smp://fingerprint@addr.b32.i2p:5223`
- Ошибка "BROKER" на шаге "Соединение" — клиент не может достучаться (из-за NAT)
- Handshake реализован но не протестирован с реальным клиентом (нет рабочего I2P)
- Возможно потребуется доработка handshake после тестирования на VPS

## Что нужно сделать дальше

1. Деплой на VPS — склонировать с GitHub, запустить setup.sh
2. Проверить I2P — убедиться что LeaseSets публикуются, адрес доступен
3. Тест с SimpleX клиентом — подключиться с телефона через I2P SOCKS proxy
4. Доработать handshake — если SimpleX клиент не проходит дальше handshake
5. Опционально: libi2pd — встроить i2pd в сервер

## Технические заметки

- SQLCipher: нужен `#define SQLITE_HAS_CODEC` перед `#include <sqlite3.h>`
- i2pd в Docker: datadir = `/home/i2pd/data`, НЕ `/var/lib/i2pd`
- SimpleX fingerprint: base64url (без padding) от SHA256 DER сертификата
- i2pd web console: `/?page=local_destinations` для списка адресов
- Порт 7070 может быть занят системным i2pd — используем 7072
