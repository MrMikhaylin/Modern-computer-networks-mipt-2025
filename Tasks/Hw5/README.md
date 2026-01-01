# Modern-computer-networks.HomeTask5
**Запуск**:
1) Генерация сертификатов
```bash
python3 generate_certificates.py
```
2) Начало записи трафика
```bash
sudo tcpdump -i lo -w tls_traffic.pcap port 8888
```
3) Старт сервера и клиента
    - сервер:
    ```bash
    export SSLKEYLOGFILE=sslkeys.log
    python3 network_app.py --mode tcp-server --tls --certfile server.crt --keyfile server.key
    ```
    - клиент:
    ```bash
    export SSLKEYLOGFILE=sslkeys.log
    python3 network_app.py --mode tcp-client --tls --cafile ca.crt
    ```
4) общение клиента с сервером, конец записи трафика.

Далее, чтобы увидеть результаты работы и расшифровать запись необходимо:
- пройти в настройки Редактирование -> Параметры -> Protocols -> TLS
- В поле "(Pre)-Master-Secret log filename" указать полный путь к sslkeys.log

В моём случае это было /home/konstantin/ModernNetworks/Hw5/sslkeys.log

- Воспользоваться появившейся опцией дешифровки сообщения