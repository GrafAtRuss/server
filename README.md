# Консоль 1.1.0

Веб-консоль для Ubuntu 24.04: установка платформы 1С, бекап конфигураций, диски и облака, бекап виртуальных машин ESXi и vSphere.

## Установка

На сервере Ubuntu 24.04:

```bash
sudo apt-get update
sudo apt-get install -y git python3 cifs-utils nfs-common sshpass
git clone https://github.com/GrafAtRuss/server.git
cd server
sudo ./build-deb.sh
sudo dpkg -i onec-console_1.1.0_all.deb
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
sudo dpkg -i onec-console_1.1.0_all.deb
```

Пароль при обновлении не сбрасывается.

## Что делает панель

1. **Установка.** Загрузите архивы сервера и толстого клиента (`server64_….zip` и `client_….deb64.zip`). Кнопка «Установить автоматически» ставит пакеты в порядке common, server, толстый клиент. Тонкий клиент и веб-модуль пропускаются.
2. **Хранилища.** WebDAV, CIFS, NFS и FTP — куда пишутся бекапы. Google Drive и Яндекс Диск подключаются токеном, Облако Mail.ru — паролем приложения через WebDAV.
3. **Базы.** У каждой информационной базы свой диск, облачные копии и расписание.
4. **Виртмашины.** Подключение ESXi или vSphere. Перед копированием машина мягко выключается, после копии включается. Копия файлов с ESXi требует `sshpass`.
5. **Доступ.** Несколько операторов, каждый меняет свой пароль.

Служба называется `onec-console` и слушает порт 8780.

```bash
systemctl status onec-console
journalctl -u onec-console -n 50
```
