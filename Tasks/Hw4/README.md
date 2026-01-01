# Modern-computer-networks.HomeTask4
**Запуск**:

Собиралась вторая схема (с fw1)

Для проверки работы фильтрации на устройстве ***fw1*** запускается скрипт
```bash
python3 http_filter.py
``` 
Вместе с ним на устройстве ***user2*** начинает работу простейший сервер
```bash
python3 -m http.server 8000
``` 
Затем, все что нужно сделать, это в терминале устройства ***user1*** ввести запрос к ***user2***

Примеры:
- **Блокирутся:**

    - Блокируется по rule1: POST + curl + admin
    ```bash
    curl -X POST -A "curl" http://192.168.20.2:8000/admin/
    ```
    - Блокируется по rule2: GET + curl + secret
    ```bash
    curl -A "curl" http://192.168.20.2:8000/secret-files/
    ```
    - Блокируется по rule3: curl + test хост
    ```bash
    curl -A "curl" http://test.example.com:8000/
    ```
    - Блокируется по rule4: POST + admin (даже с другим User-Agent)
    ```bash
    curl -X POST -A "firefox" http://192.168.20.2:8000/admin/
    ```
    - Блокируется по rule6: любой запрос от curl
    ```bash
    curl -A "curl" http://192.168.20.2:8000/normal-page/
    ```
- **Проходят:**

    - Проходит по rule5: GET + firefox
    ```bash
    curl -A "firefox" http://192.168.20.2:8000/
    ```
    - Проходит: GET + chrome (не подходит ни под одно правило блокировки)
    ```bash
    curl -A "chrome" http://192.168.20.2:8000/
    ```

    - Проходит: GET + firefox к admin (rule5 имеет приоритет как accept)
    ```bash
    curl -A "firefox" http://192.168.20.2:8000/admin/
    ```

    - Проходит: POST + firefox к normal page (не под правила блокировки)
    ```bash
    curl -X POST -A "firefox" http://192.168.20.2:8000/normal-page/
    ```

При блокировке трафика происходит блокировка терминала устройства ***user1***, так как server в лице ***user2*** должен выслать уведомление, что получил пакет, чего не происходит из-за фильтрации на устройстве ***fw1***