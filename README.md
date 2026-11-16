# Лабораторна робота 2. TLS та сертифікати

| Поле | Значення |
|---|---|
| ПІБ | Орлова Вікторія |
| Група | F5 2.02 |
| Ідентифікатор | `cs-202-17` |
| Дата виконання | 16.11.2026 |
| Середовище | GitHub Codespaces, Docker-контейнер стенда |
| Версія OpenSSL | OpenSSL 3.0.13 30 Jan 2024 (Library: OpenSSL 3.0.13 30 Jan 2024) |

## Параметри варіанта

| Параметр | Значення |
|---|---|
| Віддалений сервер | `edge.cs-202-17.lab` |
| Імена для сертифіката | `www.cs-202-17.lab`, `files.cs-202-17.lab` |
| Ваш сервер (IP) | `10.53.1.1` |

Зона DNS: `cs-202-17.lab`.

Резолвер: `10.53.0.53`.

Корінь стенда: `/lab/pki/stand-root.crt`.

Каталог ACME: `https://ca.lab:14000/dir`.

Перезапуск стенда під час виконання завдань у наданому журналі не зафіксований.

## Завдання 1. HTTP і HTTPS у дампі трафіку

### Вивід кроку 1.1

```text
[1] 37
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on eth0, link-type EN10MB (Ethernet), snapshot length 262144 bytes
server: web
Host: edge.cs-202-17.lab
SNI:
protocol: HTTP/1.1
client: 10.53.1.1
10 packets captured
10 packets received by filter
0 packets dropped by kernel
[1]+ Exit 124 timeout 8 tcpdump -ni eth0 -A -s0 -l 'host 10.53.0.80 and tcp port 80' > t1-http.txt
18:29:55.059513 IP 10.53.1.1.43200 > 10.53.0.80.80: Flags [P.], seq 1:82, ack 1, win 502, options [nop,nop,TS val 3089740937 ecr 2101563795], length 81: HTTP: GET / HTTP/1.1
.)..}CQ.GET / HTTP/1.1
Host: edge.cs-202-17.lab
server: web
Host: edge.cs-202-17.lab
```

Додаткова перевірка кількості входжень доменного імені:

```bash
grep -a -o 'edge.cs-202-17.lab' /lab/work/t1-http.txt | wc -l
```

Результат:

```text
2
```

### Вивід кроку 1.2

```text
[1] 43
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on eth0, link-type EN10MB (Ethernet), snapshot length 262144 bytes
server: web
Host: edge.cs-202-17.lab
SNI: edge.cs-202-17.lab
protocol: HTTP/2.0 TLSv1.3
client: 10.53.1.1
22 packets captured
22 packets received by filter
0 packets dropped by kernel
[1]+ Exit 124 timeout 8 tcpdump -ni eth0 -A -s0 -l 'host 10.53.0.80 and tcp port 443' > t1-https.txt
0
1
```

### Порівняння тіл відповідей

```diff
--- t1-body-http.txt
+++ t1-body-https.txt
@@ -1,5 +1,5 @@
 server: web
 Host: edge.cs-202-17.lab
-SNI:
-protocol: HTTP/1.1
+SNI: edge.cs-202-17.lab
+protocol: HTTP/2.0 TLSv1.3
 client: 10.53.1.1
```

| Що шукали в дампі | HTTP | HTTPS |
|---|---|---|
| Рядок запиту `GET /` | Видно: `GET / HTTP/1.1` | Не видно |
| Заголовок `Host` | Видно: `Host: edge.cs-202-17.lab` | Не видно у відкритому тексті |
| Тіло відповіді (`server: web`) | Видно | Не видно, результат пошуку `0` |
| Ім'я віддаленого сервера (кількість входжень) | 2 | 1 |

### Відповіді на питання

**1. У якому повідомленні і в якому полі передається ім'я сервера, яке видно в дампі HTTPS?**

Ім'я сервера передається в повідомленні `ClientHello` протоколу TLS у розширенні `server_name`, яке називається SNI (Server Name Indication).

Це розширення дозволяє серверу визначити, для якого доменного імені клієнт хоче встановити захищене з'єднання, та вибрати відповідний сертифікат.

У TLS 1.3 без використання ECH розширення SNI залишається відкритим, хоча HTTP-запит і відповідь передаються в зашифрованому вигляді.

**2. Чому рядок `SNI:` у відповіді сервера порожній для HTTP і заповнений для HTTPS?**

Для звичайного HTTP протокол TLS не використовується, тому повідомлення `ClientHello` не надсилається і розширення SNI відсутнє. Через це сервер показує порожній рядок `SNI:`.

Для HTTPS перед HTTP-запитом відбувається TLS-рукостискання. Клієнт надсилає SNI з іменем `edge.cs-202-17.lab`, тому сервер повертає `SNI: edge.cs-202-17.lab`.

**3. Що визначило версію HTTP у другому випадку?**

Версію HTTP визначило узгодження прикладного протоколу через розширення ALPN (Application-Layer Protocol Negotiation) під час TLS-рукостискання.

Клієнт запропонував серверу протоколи `h2` та `http/1.1`, а сервер вибрав `h2`, тобто HTTP/2.

Це підтверджується рядком:

```text
ALPN protocol: h2
```

Тому для HTTPS було використано HTTP/2.0, а для звичайного HTTP — HTTP/1.1.

## Завдання 2. Рукостискання по записах

### Вивід кроку 2.1 (TLS 1.3)

```text
Sent Record
  Content Type = Handshake (22)
  Length = 333
    ClientHello, Length=329
Received Record
  Content Type = Handshake (22)
  Length = 122
    ServerHello, Length=118
Received Record
  Content Type = ChangeCipherSpec (20)
  Length = 1
Received Record
  Content Type = ApplicationData (23)
  Length = 36
  Inner Content Type = Handshake (22)
    EncryptedExtensions, Length=15
Received Record
  Content Type = ApplicationData (23)
  Length = 1006
  Inner Content Type = Handshake (22)
    Certificate, Length=985
Received Record
  Content Type = ApplicationData (23)
  Length = 96
  Inner Content Type = Handshake (22)
    CertificateVerify, Length=75
Received Record
  Content Type = ApplicationData (23)
  Length = 69
  Inner Content Type = Handshake (22)
    Finished, Length=48
Sent Record
  Content Type = ChangeCipherSpec (20)
  Length = 1
Sent Record
  Content Type = ApplicationData (23)
  Length = 69
  Inner Content Type = Handshake (22)
    Finished, Length=48
Sent Record
  Content Type = ApplicationData (23)
  Length = 19
  Inner Content Type = Alert (21)
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
ALPN protocol: h2
Verify return code: 0 (ok)
```

### Вивід кроку 2.2 (TLS 1.2)

```text
Sent Record
  Content Type = Handshake (22)
    ClientHello, Length=224
Received Record
  Content Type = Handshake (22)
    ServerHello, Length=74
Received Record
  Content Type = Handshake (22)
    Certificate, Length=980
Received Record
  Content Type = Handshake (22)
    ServerKeyExchange, Length=111
Received Record
  Content Type = Handshake (22)
    ServerHelloDone, Length=0
Sent Record
  Content Type = Handshake (22)
    ClientKeyExchange, Length=33
Sent Record
  Content Type = ChangeCipherSpec (20)
Sent Record
  Content Type = Handshake (22)
    Finished, Length=12
Received Record
  Content Type = Handshake (22)
    NewSessionTicket, Length=214
Received Record
  Content Type = ChangeCipherSpec (20)
Received Record
  Content Type = Handshake (22)
    Finished, Length=12
Received Record
  Content Type = ApplicationData (23)
Sent Record
  Content Type = Alert (21)
New, TLSv1.2, Cipher is ECDHE-ECDSA-AES256-GCM-SHA384
ALPN protocol: h2
    Verify return code: 0 (ok)
```

### Послідовність записів TLS 1.3

| № | Напрям | `Content Type` | `Inner Content Type` | Повідомлення | `Length` |
|---|---|---|---|---|---|
| 1 | К→С | Handshake (22) | — | ClientHello | 333 |
| 2 | С→К | Handshake (22) | — | ServerHello | 122 |
| 3 | С→К | ChangeCipherSpec (20) | — | ChangeCipherSpec | 1 |
| 4 | С→К | ApplicationData (23) | Handshake (22) | EncryptedExtensions | 36 |
| 5 | С→К | ApplicationData (23) | Handshake (22) | Certificate | 1006 |
| 6 | С→К | ApplicationData (23) | Handshake (22) | CertificateVerify | 96 |
| 7 | С→К | ApplicationData (23) | Handshake (22) | Finished | 69 |
| 8 | К→С | ChangeCipherSpec (20) | — | ChangeCipherSpec | 1 |
| 9 | К→С | ApplicationData (23) | Handshake (22) | Finished | 69 |
| 10 | К→С | ApplicationData (23) | Alert (21) | Alert | 19 |

Довжини записів отримані з повного трасування `openssl s_client -trace`.

### Вивід кроків 2.3 і 2.4

```text
        extension_type=server_name(0), length=23
          0000 - 00 15 00 00 12 65 64 67-65 2e 63 73 2d 32 30   .....edge.cs-20
          000f - 32 2d 31 37 2e 6c 61 62-                       2-17.lab
        extension_type=ec_point_formats(11), length=4

TLS 1.3: 0
TLS 1.2: 2
```

### Порівняння TLS 1.3 і TLS 1.2

| Показник | TLS 1.3 | TLS 1.2 |
|---|---|---|
| Довжина ClientHello, байт | 329 | 224 |
| Номер першого запису, тип якого спостерігач не бачить | 4 | Внутрішній тип не приховується таким самим способом; зовнішній тип запису видимий |
| Кількість RTT від ClientHello до першого HTTP-запиту | 1 RTT | 2 RTT |
| Чи видно сертифікат у дампі (результат 2.4) | Ні (`0`) | Так (`2`) |
| Обраний протокол ALPN | h2 | h2 |

### Відповіді на питання

**1. За якими рядками визначено, з якого запису починається шифрування? Що бачить спостерігач замість типу кожного наступного запису?**

Шифрування в TLS 1.3 починається після повідомлення `ServerHello`.

У виводі це підтверджується четвертим записом:

```text
Received Record
  Content Type = ApplicationData (23)
  Length = 36
  Inner Content Type = Handshake (22)
    EncryptedExtensions, Length=15
```

Зовнішній тип запису позначено як `ApplicationData (23)`, хоча всередині передається повідомлення рукостискання.

Сторонній спостерігач бачить зовнішній тип `ApplicationData`, але не може визначити тип зашифрованого внутрішнього повідомлення.

**2. Чому ClientHello у TLS 1.3 довший, ніж у TLS 1.2? Назвіть розширення, яке скорочує рукостискання на один RTT.**

У TLS 1.3 повідомлення `ClientHello` містить додаткові розширення для узгодження криптографічних параметрів.

У цьому досліді його довжина становила 329 байт, а в TLS 1.2 — 224 байти. Різниця дорівнює 105 байтам.

Одним із головних розширень є `key_share`. Воно дозволяє клієнту передати параметри для обміну ключами вже в першому повідомленні, без необхідності чекати окремої відповіді сервера.

Завдяки цьому повне рукостискання TLS 1.3 займає приблизно 1 RTT замість 2 RTT у TLS 1.2.

**3. З яких частин складається довжина розширення server_name і якою вона буде для вашого імені?**

Розширення `server_name` містить:

- 2 байти — довжина списку імен.
- 1 байт — тип імені (`host_name`).
- 2 байти — довжина самого доменного імені.
- N байтів — доменне ім'я.

Отже, загальна довжина дорівнює N + 5 байтів.

У нашому випадку `edge.cs-202-17.lab` містить 18 символів.

Тому:

```text
18 + 5 = 23 байти
```

Це збігається з результатом:

```text
extension_type=server_name(0), length=23
```

Для `www.cs-202-17.lab` довжина становитиме 22 байти, а для `files.cs-202-17.lab` — 24 байти.

**4. Навіщо в TLS 1.3 передається ChangeCipherSpec, якщо він нічого не змінює?**

У TLS 1.3 повідомлення `ChangeCipherSpec` використовується переважно для сумісності зі старими мережевими пристроями та програмним забезпеченням, які очікують таке повідомлення під час рукостискання.

На відміну від TLS 1.2, у TLS 1.3 воно не перемикає криптографічні ключі та не змінює стан шифрування.

## Завдання 3. Сертифікат для власного сервера

### Вивід кроків 3.1 і 3.2

```text
збережено /lab/tls/acme-root.crt
subject=CN = Pebble Root CA 143744
notBefore=Nov 16 18:28:10 2026 GMT
notAfter=Nov 16 18:28:10 2056 GMT
curl: (60) SSL certificate problem: self-signed certificate
More details here: https://curl.se/docs/sslcerts.html

curl failed to verify the legitimacy of the server and therefore could not
establish a secure connection to it. To learn more about this situation and
how to fix it, please visit the web page mentioned above.
```

До отримання сертифіката ACME сервер використовував тимчасовий самопідписаний сертифікат, тому клієнт не зміг підтвердити його справжність.

### Вивід кроку 3.3

```text
2026/11/16 18:35:14 [INFO] acme: Registering account for admin@cs-202-17.lab
2026/11/16 18:35:14 [INFO] [www.cs-202-17.lab, files.cs-202-17.lab] acme: Obtaining SAN certificate
2026/11/16 18:35:15 [INFO] [www.cs-202-17.lab] AuthURL: https://ca.lab:14000/authZ/PbU2IT0-Z0KC1TT-gFY8OvtG0bLvkAfL4uer3IrTZgw
2026/11/16 18:35:15 [INFO] [files.cs-202-17.lab] AuthURL: https://ca.lab:14000/authZ/8NLDL_1ydaoM9dNCLczLtiEEZD9IWIZ24RvwTyEqJiQ
2026/11/16 18:35:15 [INFO] [www.cs-202-17.lab] acme: Could not find solver for: tls-alpn-01
2026/11/16 18:35:15 [INFO] [www.cs-202-17.lab] acme: use http-01 solver
2026/11/16 18:35:15 [INFO] [files.cs-202-17.lab] acme: Could not find solver for: tls-alpn-01
2026/11/16 18:35:15 [INFO] [files.cs-202-17.lab] acme: use http-01 solver
2026/11/16 18:35:15 [INFO] [www.cs-202-17.lab] acme: Trying to solve HTTP-01
2026/11/16 18:35:17 [INFO] [www.cs-202-17.lab] The server validated our request
2026/11/16 18:35:17 [INFO] [files.cs-202-17.lab] acme: Trying to solve HTTP-01
2026/11/16 18:35:22 [INFO] [files.cs-202-17.lab] The server validated our request
2026/11/16 18:35:22 [INFO] [www.cs-202-17.lab, files.cs-202-17.lab] acme: Validations succeeded; requesting certificates
2026/11/16 18:35:22 [INFO] Wait for certificate [timeout: 30s, interval: 500ms]
2026/11/16 18:35:22 [INFO] [www.cs-202-17.lab] Server responded with a certificate.
```

Журнал nginx:

```text
10.53.0.10 - - [16/Nov/2026:18:35:15 +0000] "GET /.well-known/acme-challenge/hLVdMhPJkiOuCec8e5WClwKjjMabpYsqulxlPEsb2Yo HTTP/1.1" 200 87 "-" "LetsEncrypt-Pebble-VA (linux; amd64)"
10.53.0.10 - - [16/Nov/2026:18:35:15 +0000] "GET /.well-known/acme-challenge/hLVdMhPJkiOuCec8e5WClwKjjMabpYsqulxlPEsb2Yo HTTP/1.1" 200 87 "-" "LetsEncrypt-Pebble-VA (linux; amd64)"
10.53.0.10 - - [16/Nov/2026:18:35:15 +0000] "GET /.well-known/acme-challenge/hLVdMhPJkiOuCec8e5WClwKjjMabpYsqulxlPEsb2Yo HTTP/1.1" 200 87 "-" "LetsEncrypt-Pebble-VA (linux; amd64)"
10.53.0.10 - - [16/Nov/2026:18:35:17 +0000] "GET /.well-known/acme-challenge/k06-jLUqsALapz6ISNQ01SrTOWklogrGixlXxVo9CZY HTTP/1.1" 200 87 "-" "LetsEncrypt-Pebble-VA (linux; amd64)"
10.53.0.10 - - [16/Nov/2026:18:35:17 +0000] "GET /.well-known/acme-challenge/k06-jLUqsALapz6ISNQ01SrTOWklogrGixlXxVo9CZY HTTP/1.1" 200 87 "-" "LetsEncrypt-Pebble-VA (linux; amd64)"
10.53.0.10 - - [16/Nov/2026:18:35:17 +0000] "GET /.well-known/acme-challenge/k06-jLUqsALapz6ISNQ01SrTOWklogrGixlXxVo9CZY HTTP/1.1" 200 87 "-" "LetsEncrypt-Pebble-VA (linux; amd64)"
```

### Вивід кроку 3.4

```text
subject=CN = www.cs-202-17.lab
issuer=CN = Pebble Intermediate CA 55d9fa
notBefore=Nov 16 18:35:22 2026 GMT
notAfter=Nov 16 18:35:21 2031 GMT
serial=5092A971485CD5AC
X509v3 Subject Alternative Name:
    DNS:www.cs-202-17.lab, DNS:files.cs-202-17.lab
subject=CN = Pebble Intermediate CA 55d9fa
issuer=CN = Pebble Root CA 143744
```

### Вивід кроку 3.5

```text
nginx: the configuration file /lab/nginx.conf syntax is ok
nginx: configuration file /lab/nginx.conf test is successful
2026/11/16 18:36:28 [notice] 95#95: signal process started
curl: (60) SSL certificate problem: unable to get local issuer certificate
More details here: https://curl.se/docs/sslcerts.html

curl failed to verify the legitimacy of the server and therefore could not
establish a secure connection to it. To learn more about this situation and
how to fix it, please visit the web page mentioned above.
Certificate chain
 0 s:CN = www.cs-202-17.lab
   i:CN = Pebble Intermediate CA 55d9fa
   a:PKEY: id-ecPublicKey, 256 (bit); sigalg: RSA-SHA256
   v:NotBefore: Nov 16 18:35:22 2026 GMT; NotAfter: Nov 16 18:35:21 2031 GMT
---
Verify return code: 21 (unable to verify the first certificate)
```

### Вивід кроку 3.6

```text
nginx: the configuration file /lab/nginx.conf syntax is ok
nginx: configuration file /lab/nginx.conf test is successful
2026/11/16 18:37:42 [notice] 103#103: signal process started
server: cs-202-17 (https)
Host: www.cs-202-17.lab
SNI: www.cs-202-17.lab
protocol: TLSv1.3
server: cs-202-17 (https)
Host: files.cs-202-17.lab
SNI: files.cs-202-17.lab
protocol: TLSv1.3
Certificate chain
 0 s:CN = www.cs-202-17.lab
   i:CN = Pebble Intermediate CA 55d9fa
   a:PKEY: id-ecPublicKey, 256 (bit); sigalg: RSA-SHA256
   v:NotBefore: Nov 16 18:35:22 2026 GMT; NotAfter: Nov 16 18:35:21 2031 GMT
 1 s:CN = Pebble Intermediate CA 55d9fa
   i:CN = Pebble Root CA 143744
   a:PKEY: rsaEncryption, 2048 (bit); sigalg: RSA-SHA256
   v:NotBefore: Nov 16 18:28:10 2026 GMT; NotAfter: Nov 16 18:28:10 2056 GMT
---
Verify return code: 0 (ok)
```

### Параметри отриманого сертифіката

| Параметр | Значення |
|---|---|
| Видавець сертифіката сервера | Pebble Intermediate CA 55d9fa |
| Видавець сертифіката видавця | Pebble Root CA 143744 |
| Імена в SAN | `www.cs-202-17.lab`, `files.cs-202-17.lab` |
| Строк дії | 16.11.2026 18:35:22 — 16.11.2031 18:35:21 GMT |
| Тип ключа сервера і алгоритм підпису | EC, 256 біт; RSA-SHA256 |
| Кількість сертифікатів, які надсилає сервер, у кроці 3.5 і в кроці 3.6 | 1 та 2 відповідно |

### Відповіді на питання

**1. Хто і як перевірив, що ви контролюєте обидва імена?**

Контроль над доменними іменами перевірив центр сертифікації ACME Pebble методом HTTP-01.

Клієнт `lego` розмістив спеціальні файли перевірки у каталозі `/.well-known/acme-challenge/`. Центр сертифікації виконав HTTP-запити до цих файлів та перевірив їхній вміст.

У журналі nginx видно, що запити завершилися з кодом `200`.

Успішну перевірку підтверджують рядки:

```text
[www.cs-202-17.lab] The server validated our request
[files.cs-202-17.lab] The server validated our request
[www.cs-202-17.lab, files.cs-202-17.lab] acme: Validations succeeded; requesting certificates
```

Після перевірки центр сертифікації видав сертифікат для обох імен.

**2. Чому в кроці 3.5 перевірка не пройшла, хоча корінь центру сертифікації вказано в --cacert, а сертифікат виданий правильно?**

Сервер надсилав тільки власний сертифікат, але не надсилав сертифікат проміжного центру сертифікації.

Клієнт довіряв кореневому сертифікату Pebble, проте не міг побудувати повний ланцюжок довіри від сертифіката сервера до кореневого CA.

Це підтверджується помилкою:

```text
curl: (60) SSL certificate problem: unable to get local issuer certificate
Verify return code: 21 (unable to verify the first certificate)
```

Після додавання проміжного сертифіката та перезавантаження nginx перевірка завершилася успішно:

```text
Verify return code: 0 (ok)
```

**3. Що означають id-ecPublicKey і RSA-SHA256? Чому вони не суперечать одне одному?**

`id-ecPublicKey` означає, що відкритий ключ сервера використовує криптографію на еліптичних кривих. У цьому випадку довжина ключа становить 256 біт.

`RSA-SHA256` означає, що центр сертифікації підписав сертифікат за допомогою алгоритму RSA з хеш-функцією SHA-256.

Ці параметри не суперечать один одному, оскільки перший описує тип відкритого ключа сервера, а другий — алгоритм підпису сертифіката центром сертифікації.

**4. Що станеться з перевіркою сервера після перезапуску стенда і чому? Що в реальній інфраструктурі відповідає цій ситуації?**

Після перезапуску стенда центр Pebble створює новий кореневий і проміжний ключі.

Раніше виданий сертифікат був підписаний попереднім центром сертифікації, тому він більше не проходитиме перевірку з новим кореневим сертифікатом.

Для відновлення працездатності необхідно повторно отримати кореневий сертифікат ACME, перевидати сертифікат сервера та встановити правильний ланцюжок.

У реальній інфраструктурі схожа ситуація виникає під час зміни центру сертифікації, ротації кореневих ключів або зміни сховища довірених сертифікатів.

## Завдання 4. Діагностика несправностей

### Вивід кроку 4.1

```text
=== f1.cs-202-17.lab
curl: (60) SSL certificate problem: self-signed certificate
Certificate chain
 0 s:CN = f1.cs-202-17.lab
   i:CN = f1.cs-202-17.lab
   v:NotBefore: Nov 16 18:28:08 2026 GMT; NotAfter: Feb 14 18:28:08 2027 GMT
---
Verify return code: 18 (self-signed certificate)

=== f2.cs-202-17.lab
curl: (60) SSL certificate problem: unable to get local issuer certificate
Certificate chain
 0 s:CN = f2.cs-202-17.lab
   i:O = OPISM Lab, CN = OPISM Stand Intermediate CA
   v:NotBefore: Nov 16 18:28:08 2026 GMT; NotAfter: Feb 14 18:28:08 2027 GMT
---
Verify return code: 21 (unable to verify the first certificate)

=== f3.cs-202-17.lab
server: web, f3
Certificate chain
 0 s:CN = f3.cs-202-17.lab
   i:O = OPISM Lab, CN = OPISM Stand Intermediate CA
   v:NotBefore: Nov 16 18:28:09 2026 GMT; NotAfter: Feb 14 18:28:09 2027 GMT
 1 s:O = OPISM Lab, CN = OPISM Stand Intermediate CA
   i:O = OPISM Lab, CN = OPISM Stand Root CA
   v:NotBefore: Nov 16 18:28:08 2026 GMT; NotAfter: Nov 15 18:28:08 2031 GMT
---
Verify return code: 0 (ok)

=== f4.cs-202-17.lab
curl: (60) SSL: no alternative certificate subject name matches target host name 'f4.cs-202-17.lab'
Certificate chain
 0 s:CN = intra.cs-202-17.lab
   i:O = OPISM Lab, CN = OPISM Stand Intermediate CA
   v:NotBefore: Nov 16 18:28:09 2026 GMT; NotAfter: Feb 14 18:28:09 2027 GMT
 1 s:O = OPISM Lab, CN = OPISM Stand Intermediate CA
   i:O = OPISM Lab, CN = OPISM Stand Root CA
   v:NotBefore: Nov 16 18:28:08 2026 GMT; NotAfter: Nov 15 18:28:08 2031 GMT
---
Verify return code: 0 (ok)

=== f5.cs-202-17.lab
curl: (60) SSL certificate problem: unable to get local issuer certificate
Certificate chain
 0 s:CN = f5.cs-202-17.lab
   i:O = Foreign Org, CN = Foreign Intermediate CA
   v:NotBefore: Nov 16 18:28:09 2026 GMT; NotAfter: Feb 14 18:28:09 2027 GMT
 1 s:O = Foreign Org, CN = Foreign Intermediate CA
   i:O = Foreign Org, CN = Foreign Root CA
   v:NotBefore: Nov 16 18:28:08 2026 GMT; NotAfter: Nov 15 18:28:08 2031 GMT
---
Verify return code: 20 (unable to get local issuer certificate)
```

### Додаткова перевірка f4

```text
=== f4.cs-202-17.lab
verify error:num=62:hostname mismatch
Verify return code: 62 (hostname mismatch)
subject=CN = intra.cs-202-17.lab
issuer=O = OPISM Lab, CN = OPISM Stand Intermediate CA
notBefore=Nov 16 18:28:09 2026 GMT
notAfter=Feb 14 18:28:09 2027 GMT
X509v3 Subject Alternative Name:
    DNS:intra.cs-202-17.lab
```

### Таблиця діагностики

| Сервер | Помилка `curl` | `Verify return code` | Яка перевірка не пройшла | Рядок виводу, що це доводить | Що має змінити власник сервера |
|---|---|---|---|---|---|
| f1 | self-signed certificate | 18 | Самопідписаний сертифікат | `Verify return code: 18` | Отримати сертифікат від довіреного CA |
| f2 | unable to get local issuer certificate | 21 | Відсутній проміжний сертифікат | `Verify return code: 21`; у ланцюжку лише сертифікат `0` | Додати проміжний сертифікат |
| f3 | Помилки немає | 0 (ok) | Усі перевірки пройдено | `Verify return code: 0 (ok)` | Нічого змінювати не потрібно |
| f4 | no alternative certificate subject name matches target host name | 0 без перевірки імені, 62 з перевіркою імені | Невідповідність SAN | `verify error:num=62:hostname mismatch` | Перевидати сертифікат з правильним SAN |
| f5 | unable to get local issuer certificate | 20 | Недовірений CA | `Verify return code: 20`; видавець `Foreign Root CA` | Отримати сертифікат від довіреного CA |

### Відповіді на питання

**1. Для сервера з помилкою unable to get local issuer certificate визначте, яка це несправність. Чим вони відрізняються у виводі openssl s_client?**

У цьому варіанті сервери `f2` та `f5` мають схожі помилки, але різні причини.

У сервера `f2` відсутній проміжний сертифікат. У виводі `Certificate chain` присутній лише кінцевий сертифікат, який підписаний `OPISM Stand Intermediate CA`.

Результат:

```text
Verify return code: 21 (unable to verify the first certificate)
```

У сервера `f5` проміжний сертифікат присутній, але він підписаний недовіреним центром `Foreign Root CA`.

Результат:

```text
Verify return code: 20 (unable to get local issuer certificate)
```

Отже, основна відмінність полягає у складі ланцюжка сертифікатів та центрі сертифікації, до якого він веде.

**2. Чому openssl s_client для сервера з невідповідним ім'ям повертає Verify return code: 0 (ok), а curl повідомляє про помилку?**

За замовчуванням використана команда `openssl s_client` перевіряє ланцюжок сертифікатів, але не перевіряє відповідність сертифіката конкретному доменному імені без додаткового параметра.

Натомість `curl` автоматично перевіряє відповідність імені сервера записам у SAN.

Для сервера `f4` сертифікат виданий на `intra.cs-202-17.lab`, хоча клієнт звертається до `f4.cs-202-17.lab`.

Тому `curl` повернув помилку невідповідності імені.

Після використання параметра:

```bash
-verify_hostname f4.cs-202-17.lab
```

OpenSSL також виявив помилку:

```text
Verify return code: 62 (hostname mismatch)
```

**3. Які з п'яти серверів відповіли б на запит curl -k? Що при цьому втрачається порівняно з --cacert?**

Очікується, що всі п'ять серверів зможуть відповісти на запит `curl -k`, оскільки їхні несправності пов'язані з перевіркою сертифікатів.

Параметр `-k` вимикає перевірку довіри до сертифіката та відповідності доменного імені.

При цьому TLS-шифрування зберігається, але клієнт більше не може надійно підтвердити справжність сервера.

Це створює небезпеку атаки «людина посередині» (Man-in-the-Middle).

На відміну від `-k`, параметр `--cacert` дозволяє явно вказати довірений кореневий сертифікат, зберігаючи перевірку автентичності сервера.

Окремий запуск `curl -k` у журналі не зафіксовано, тому це прогнозований результат.

## Завдання 5. Ціна нового з'єднання

### Прогноз

Прогноз для повного рукостискання без відновлення сесії. Передбачається, що DNS-пошук до кешувального резолвера займає приблизно один RTT.

| Етап | TLS 1.3, нове з'єднання | TLS 1.2, нове з'єднання | Повторне використання з'єднання |
|---|---|---|---|
| `time_connect` | 2 RTT | 2 RTT | 0 RTT |
| `time_appconnect` | 3 RTT | 4 RTT | 0 RTT |
| `time_starttransfer` | 4 RTT | 5 RTT | 1 RTT |

Для нового з'єднання TLS 1.3 очікується 1 RTT для DNS, 1 RTT для TCP, 1 RTT для TLS та 1 RTT до першого байта HTTP-відповіді.

Для TLS 1.2 рукостискання зазвичай займає 2 RTT, тому загальний час більший.

При повторному використанні з'єднання TCP- та TLS-рукостискання не повторюються.

### Вивід кроків 5.2 і 5.3

TLS 1.3:

```text
0.050770 0.076078 0.104972 0.130279 0.130326 2 1
0.025371 0.050487 0.084044 0.109491 0.109546 2 1
0.025701 0.050846 0.078932 0.104169 0.104248 2 1
```

TLS 1.2:

```text
0.025431 0.050661 0.104157 0.129445 0.129502 2 1
0.025409 0.050514 0.103960 0.129251 0.129307 2 1
0.025389 0.050500 0.103736 0.129028 0.129091 2 1
```

Повторне використання з'єднання:

```text
0.025453 0.050591 0.078569 0.104346 0.104390 2 1
0.000017 0.000000 0.000000 0.025185 0.025222 2 0
0.000011 0.000000 0.000000 0.025246 0.025274 2 0
```

### Результати вимірювань

Усі значення часу наведено в мілісекундах. Для нових з'єднань використано медіану трьох вимірювань.

| Запит | `namelookup` | `connect` | `appconnect` | `starttransfer` | `total` | `num_connects` |
|---|---:|---:|---:|---:|---:|---:|
| TLS 1.3, нове | 25.701 | 50.846 | 84.044 | 109.491 | 109.546 | 1 |
| TLS 1.2, нове | 25.409 | 50.514 | 103.960 | 129.251 | 129.307 | 1 |
| 5.3, перший запит | 25.453 | 50.591 | 78.569 | 104.346 | 104.390 | 1 |
| 5.3, другий запит | 0.017 | 0.000 | 0.000 | 25.185 | 25.222 | 0 |
| 5.3, третій запит | 0.011 | 0.000 | 0.000 | 25.246 | 25.274 | 0 |

### Визначення RTT

Величину RTT визначаємо за різницею між часом встановлення TCP-з'єднання та часом DNS-пошуку:

`RTT ≈ time_connect - time_namelookup`

Для другого вимірювання TLS 1.3:

```text
RTT = 0.050487 - 0.025371
RTT = 0.025116 с
RTT = 25.116 мс
```

За всіма шістьма новими TCP-з'єднаннями отримано такі значення RTT:

```text
25.308 мс
25.116 мс
25.145 мс
25.230 мс
25.105 мс
25.111 мс
```

Медіана:

```text
RTT = (25.116 + 25.145) / 2
RTT = 25.1305 мс
```

Отже, для подальших розрахунків приймаємо:

**RTT ≈ 25.13 мс.**

### Відповіді на питання

**1. Виразіть кожне виміряне значення через RTT. Де вимірювання відрізняються від цілого числа RTT і чим це пояснюється?**

За RTT приблизно 25.13 мс отримуємо такі співвідношення.

Для TLS 1.3:

```text
time_namelookup:    25.701 / 25.13 ≈ 1.02 RTT
time_connect:       50.846 / 25.13 ≈ 2.02 RTT
time_appconnect:    84.044 / 25.13 ≈ 3.34 RTT
time_starttransfer: 109.491 / 25.13 ≈ 4.36 RTT
```

Для TLS 1.2:

```text
time_namelookup:    25.409 / 25.13 ≈ 1.01 RTT
time_connect:       50.514 / 25.13 ≈ 2.01 RTT
time_appconnect:    103.960 / 25.13 ≈ 4.14 RTT
time_starttransfer: 129.251 / 25.13 ≈ 5.14 RTT
```

Для першого запиту з повторним використанням:

```text
time_namelookup:    ≈ 1.01 RTT
time_connect:       ≈ 2.01 RTT
time_appconnect:    ≈ 3.13 RTT
time_starttransfer: ≈ 4.15 RTT
```

Для другого і третього запитів час до першого байта відповіді становив приблизно один RTT.

Вимірювання не завжди точно відповідають цілому числу RTT через додатковий час на обробку криптографічних операцій, роботу операційної системи, планування процесів, обробку запиту сервером і можливі коливання мережевої затримки.

**2. Чому time_namelookup не близький до нуля, хоча резолвер уже має ім'я в кеші? За яких умов він був би приблизно вдвічі більшим?**

Навіть якщо DNS-резолвер уже має потрібний запис у кеші, клієнт повинен надіслати йому запит і отримати відповідь.

Тому DNS-пошук усе одно потребує мережевого обміну, який у цьому стенді займає приблизно один RTT.

У більшості вимірювань `time_namelookup` становив близько 0.025 секунди.

Водночас у першому вимірюванні TLS 1.3 отримано:

```text
time_namelookup = 0.050770
```

Це приблизно два RTT.

Такий результат може виникати, коли для отримання відповіді потрібен додатковий мережевий обмін, наприклад, якщо потрібного запису немає в кеші резолвера.

Точну причину цього результату без окремого аналізу DNS-трафіку визначити неможливо.

**3. Сервіс виконує 200 послідовних запитів. Розрахуйте час очікування мережі для TLS 1.3, TLS 1.2 і повторного використання з'єднання.**

Використовуємо RTT = 25.1305 мс.

Припускаємо, що кожне нове з'єднання потребує окремого DNS-запиту з мережевою затримкою один RTT.

Для нового TLS 1.3 кожен запит займає приблизно 4 RTT:

```text
200 × 4 RTT = 800 RTT

800 × 25.1305 = 20104.4 мс

Результат: ≈ 20.10 с
```

Для нового TLS 1.2 кожен запит займає приблизно 5 RTT:

```text
200 × 5 RTT = 1000 RTT

1000 × 25.1305 = 25130.5 мс

Результат: ≈ 25.13 с
```

Для повторного використання одного з'єднання TLS 1.3 перший запит займає приблизно 4 RTT, а наступні 199 запитів — по одному RTT:

```text
4 RTT + 199 × 1 RTT = 203 RTT

203 × 25.1305 = 5101.49 мс

Результат: ≈ 5.10 с
```

Порівняння:

| Спосіб виконання 200 запитів | Час мережевого очікування |
|---|---:|
| Нове TLS 1.3 для кожного запиту | ≈ 20.10 с |
| Нове TLS 1.2 для кожного запиту | ≈ 25.13 с |
| Одне повторно використовуване TLS 1.3 з'єднання | ≈ 5.10 с |

Отже, повторне використання HTTPS-з'єднання дозволяє значно скоротити час мережевого очікування, оскільки не потрібно повторювати TCP- та TLS-рукостискання для кожного запиту.

## Висновки

Під час лабораторної роботи я дослідила особливості протоколів HTTP, HTTPS, TLS 1.2 і TLS 1.3, процес отримання TLS-сертифікатів через ACME, побудову ланцюжка довіри та вплив рукостискання на швидкість встановлення з'єднання.

У першому завданні встановила, що HTTP передає дані відкритим текстом. У мережевому дампі було видно рядок `GET / HTTP/1.1`, заголовок `Host` і тіло відповіді сервера. Для HTTPS ці дані були зашифровані, проте доменне ім'я залишалося доступним у SNI.

У другому завданні дослідила відмінності TLS 1.2 і TLS 1.3. Встановила, що TLS 1.3 використовує коротше рукостискання та шифрує більшість повідомлень уже після `ServerHello`. У TLS 1.2 сертифікат сервера передається у відкритому вигляді, тоді як у TLS 1.3 він захищений шифруванням.

У третьому завданні успішно отримала сертифікат ACME для доменів `www.cs-202-17.lab` і `files.cs-202-17.lab`. Після встановлення тільки кінцевого сертифіката перевірка не пройшла через відсутній проміжний сертифікат. Додавання повного ланцюжка виправило проблему, що підтверджується результатом `Verify return code: 0 (ok)`.

У четвертому завданні діагностувала п'ять серверів. Виявила самопідписаний сертифікат, неповний ланцюжок довіри, невідповідність доменного імені та використання недовіреного центру сертифікації. Сервер `f3.cs-202-17.lab` пройшов усі перевірки.

У п'ятому завданні експериментально визначила RTT, який становив приблизно 25.13 мс. Встановила, що нове з'єднання TLS 1.3 зазвичай потребує меншого часу, ніж TLS 1.2, а повторне використання з'єднання значно зменшує затримку наступних HTTPS-запитів.

### Що виявилося несподіваним

Несподіваним стало те, що в першому вимірюванні TLS 1.3 час DNS-пошуку виявився майже вдвічі більшим, ніж у наступних вимірюваннях.

Це видно з таких рядків:

```text
0.050770 0.076078 0.104972 0.130279 0.130326 2 1
0.025371 0.050487 0.084044 0.109491 0.109546 2 1
0.025701 0.050846 0.078932 0.104169 0.104248 2 1
```

Перше значення `time_namelookup` становить 50.770 мс, тоді як наступні — приблизно 25 мс.

Крім того, друге вимірювання TLS 1.3 показало збільшений час TLS-рукостискання, який перевищив оцінку одного RTT.

Це показує, що реальні мережеві вимірювання можуть відрізнятися від теоретичних моделей через додаткові накладні витрати та коливання затримки.

### Яке питання залишилося без відповіді

Не вдалося точно встановити причину збільшення часу TLS-рукостискання у другому вимірюванні TLS 1.3.

У цьому випадку:

```text
time_appconnect = 0.084044 с
time_connect = 0.050487 с

T_TLS = 0.084044 - 0.050487
T_TLS = 0.033557 с = 33.557 мс
```

Отримане значення перевищує оцінений RTT приблизно 25.13 мс.

Було перевірено часові показники TCP-з'єднань та порівняно їх із наступним вимірюванням, де TLS-етап тривав приблизно 28.086 мс.

Однак лише за результатами `curl` неможливо однозначно визначити, яка частина додаткового часу пов'язана з обробкою сервером, роботою клієнта або коливаннями мережі.

Для точнішого аналізу необхідні додаткові вимірювання часових міток TLS-записів за допомогою `tcpdump`.

## Декларація використання ШІ

Використовувалися інструменти ШІ: **так**.

| № | Інструмент | Промпт (дослівно) | Що використано у звіті і що змінено самостійно |
|---|---|---|---|
| 1 | ChatGPT | ` допоможи сформувати мд файл по шаблону ` | Використано допомогу ШІ для оформлення Markdown-файлу `README.md`, структурування таблиць і пояснення результатів. |

Додаткові дані варіанта та виводи команд були надані користувачем. Інструмент ШІ використовувався для пояснення результатів, структурування звіту та розрахунків. Вимірювання виконані у лабораторному стенді.
