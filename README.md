 
##Squid eCAP PageTitle Logger Module

adapter_pagetitle.cc

v0.1-1 (2016.06.15)

by red_neon https://github.com/redneon

Squid eCAP PageTitle Logger Module

based on adapter_modifying.cc (ecap_adapter_sample-1.0.0) http://e-cap.org/
  
 * Logging of titles of html pages into log-file via eCap module for Squid.
 * Support of pages, which compressed via Gzip or Deflate. And you can enable 
  to keep only these types of compress (see squid.conf settings)
 * Support of page titles with JSON/JSONP callback on sites:
- google.
- yandex.
- go.mail.ru
- youtube.
 
 * Support of pages with codepages: UTF-8, Windows-1251 (all another will be saved as is)
 * Support of chunked pages (limit 64000 bytes)
  See README for more information.

##### Sources:
  
http://www.squid-cache.org/

http://e-cap.org/

https://github.com/danielaparker/jsoncons

https://github.com/Iyamoto/iconv-lite

http://windrealm.org/tutorials/decompress-gzip-stream.php
 
 
 
 
##### [RUS] 
Модуль для журналирования заголовков <title>ЗАГОЛОВОК</title> на страницах
html в Squid.
- умеет читать страницы, сжатые с помощью gzip и deflate.
- поддерживает изменение заголовка запросов "Accept-Encoding" на понятные
адаптеру методы сжатия. Если там будет что то отличное от gzip, deflate,
identity, то лишнее будет вычищено
- поддерживает поиск заголовков внутри JSON/JSONP на сайтах гугла, яндекса
мейл.ру, ютюба.
- умеет собирать chunked ответы (лимит 64000 байт) без задержек.
- поддерживает конвертирование cp1251 в utf-8 на основе выдаваемого типа
содержимого в заголовке ответа.

В коде полно комментов и дебаг принтов, позже возможно будет почищено.
 
 
 
 
 
### INSTALLATION



Required libecap v1.0.*

If you don't have installed libecap v1.0.*:

Debian wheezy/jessie:
```
echo "deb-src http://http.debian.net/debian testing main" >> /etc/apt/sources.list.d/testing.list \
  && apt-get build-dep -y libecap \
  && apt-get purge libecap2 \
  && apt-get update \
  && cd /usr/src \
  && apt-get source libecap3/testing \
  && cd /usr/src/libecap-*/ \
  && dpkg-buildpackage -us -uc -nc -d \
  && cd /usr/src/ \
  && dpkg -i $(ls libecap3*.deb)
```
Debian stretch:
```
apt-get install libecap3
```


This project include jsoncons libs v0.99.1.
You can get last version of jsoncons here https://github.com/danielaparker/jsoncons
and put src/jsoncons and src/jsoncons_ext into src/

```
cd squid_ecap_pagetitle_module/
./configure CXXFLAGS=-O3
 make
 make install
```

You can find the adapter in
/usr/local/lib/ecap_adapter_pagetitle.so


If you want to re-create autoconf files:
autoreconf -vfi



### SETTINGS



Don't forget to change setting of "logfile" in ecap_service, 
default: logfile=/var/log/squid3/page_titles.log

Example of settings in squid.conf configuration file

```
# send needed info from squid into pagetitle adapter
adaptation_send_client_ip on
adaptation_send_username on
adaptation_meta X-Squid-Timestamp "%ts.%03tu"
# you can add into X-PageTitle-Custom header all what you want to see in PageTitle logs. This info will shows on end of line.
adaptation_meta X-PageTitle-Custom "referer %{Referer}>h \"%{User-Agent}>h\" %>eui"

ecap_enable on
loadable_modules /usr/local/lib/ecap_adapter_pagetitle.so
ecap_service eRespmod respmod_precache bypass=on uri=ecap://example.com/ecap_pagetitle logfile=/var/log/squid3/page_titles.log
acl http_status_ok http_status 200
adaptation_access eRespmod allow http_status_ok
## eReqmod is needed for changing of header "Accept-Encoding". This will be keep only: gzip, deflate, identity values.
## You can to remove lines below, but for example, google.com uses "sdch" compression, which the adapter does not know.
ecap_service eReqmod reqmod_precache bypass=on uri=ecap://example.com/ecap_pagetitle logfile=/var/log/squid3/page_titles.log
adaptation_access eReqmod allow all
```



### LOGS

How to read lines in log:

```timestamp client_ip username domain "page_title" url "content_type" custom_meta```

Example:

```1465966583.025 192.168.111.100 - www.google.ru "Google" https://www.google.ru/ "text/html; charset=UTF-8" referer https://www.google.ru/ "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.84 Safari/537.36" 0b:0a:22:13:53:13```


### LOGROTATE


You must do "squid -k reconfigure" after rotation of log, and only "mv" (not rm).
if you deleted log with "rm", then you must restart the Squid.

Example:
```
mv /var/log/squid3/page_titles.log /var/log/squid3/page_titles.log.0
squid -k reconfigure
```
