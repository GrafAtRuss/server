# Консоль платформы 1.2.8

Веб-консоль для Ubuntu 24.04: установка платформы 1С, бекап конфигураций, диски и облака, бекап виртуальных машин ESXi и vSphere.

## Установка

На сервере Ubuntu 24.04:

```bash
sudo apt-get update
sudo apt-get install -y git python3 cifs-utils nfs-common sshpass
git clone https://github.com/GrafAtRuss/server.git
cd server
sudo ./build-deb.sh
sudo dpkg -i onec-console_1.2.8_all.deb
sudo cat /etc/onec-console/initial-password
```

Пароль первого входа лежит только в этом файле. На странице входа его нет. Панель открывается по адресу `http://<адрес-сервера>:8780`. После смены пароля в разделе «Доступ» файл удаляется.

Если порт закрыт брандмауэром:

```bash
sudo ufw allow 8780/tcp
```

Повторная установка поверх уже работающей службы:

```bash
cd server
git pull
sudo ./build-deb.sh
sudo dpkg -i onec-console_1.2.8_all.deb
```

Пароль при обновлении не сбрасывается.

## Что делает панель

1. **Установка.** Загрузите архивы сервера и клиента. Если тонкий клиент лежит отдельно, загрузите и его. Ставятся common, server, толстый и тонкий клиент.
2. **Хранилища.** WebDAV, CIFS, NFS и FTP — куда пишутся бекапы. У каждого подключения можно открыть содержимое. Google Drive и Яндекс Диск подключаются токеном, Облако Mail.ru — паролем приложения через WebDAV.
3. **Базы.** Кластер запоминается, база выбирается из списка rac. У одной базы несколько бекапов. Всё старше срока из расписания удаляется.
4. **Машины.** ESXi или vSphere запоминается, машина выбирается из списка. Перед копией она мягко выключается, после копии включается. Копия файлов с ESXi требует `sshpass`.
5. **Система.** Имя хоста, часовой пояс, NTP, DNS, фаервол, SSH и локаль.
6. **Обслуживание.** Перезагрузка, выключение и обновление кода с GitHub.
7. **Релиз.** Описание читается из этого README на GitHub. История версий — из [CHANGELOG.md](https://github.com/GrafAtRuss/server/blob/main/CHANGELOG.md).

Служба называется `onec-console` и слушает порт 8780.

```bash
systemctl status onec-console
journalctl -u onec-console -n 50
```
