# Modern-computer-networks.HomeTask2
**Запуск**:
- Для tcp-протокола:

```bash
python network_app.py --mode tcp-server --port 8888
python network_app.py --mode tcp-client --port 8888
```
здесь port 8888 стоит по умолчанию, при запуске его писать не обязательно, но есть опция изменения port, а также host (default=localhost)

- Для udp-протокола соответственно:

```bash
python network_app.py --mode udp-server --port 8889
python network_app.py --mode udp-client --port 8889
```
здесь также port 8889 стоит по умолчанию, при запуске его писать не обязательно, но есть опция изменения port, а также host (default=localhost)

Порты по умолчанию различны для протоколов во избежание конфликтов при одновременном запуске.

Далее работа с каждой системой понятна: на клиенте можем писать серверу, на сервере можем писать клиентам по их client_id, делать broadcast рассылку, смотреть список подключенных/ранее писавших клиентов. Также клиент может получать статистику сервера командой /stats и играть в пинг-понг сообщения со стороны клиента командой /ping.

**Тест систем** на возможность передавать большие сообщения проводился следующей командой (пример для tcp (port 8888)): 

```bash
dd if=/dev/zero bs=1024 count=20 | tr '\0' 'A' > large_msg.txt
echo "" >> large_msg.txt
nc localhost 8888 < large_msg.txt
```

**Расшифровка сетевого дампа (in general)**
1) tcp-protocol:
    - broadcast from server >> hi everyone
    - client to server >> hi, i am your client
2) udp-protocol:
    - client to server >> hi server, i am your client number one
    - server to client >> hi, you are my only client