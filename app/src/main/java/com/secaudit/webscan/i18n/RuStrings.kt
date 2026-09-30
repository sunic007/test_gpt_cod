package com.secaudit.webscan.i18n

object RuStrings : Strings() {

    override val lang = Lang.RU

    override val map = mapOf(
        // ---------------------------------------------------------------- chrome
        "ui.app.title" to "АУДИТ БЕЗОПАСНОСТИ САЙТА",
        "ui.auth.title" to "НУЖНО РАЗРЕШЕНИЕ",
        "ui.auth.body" to "Сканирование чужих систем без разрешения владельца может быть " +
            "незаконным. Подтвердите, что сайт принадлежит вам или у вас есть письменное " +
            "разрешение на его проверку.",
        "ui.auth.check" to "У меня есть право проверять этот сайт",
        "ui.target.label" to "ЦЕЛЬ",
        "ui.target.hint" to "example.com",
        "ui.action.scan" to "ЗАПУСТИТЬ АУДИТ",
        "ui.action.reset" to "ОЧИСТИТЬ",
        "ui.action.export" to "ПОДЕЛИТЬСЯ",
        "ui.sec.history" to "ИСТОРИЯ",
        "ui.history.clear" to "ОЧИСТИТЬ ВСЁ",

        // ------------------------------------------------------------ lab screen
        "ui.tab.audit" to "АУДИТ",
        "ui.tab.lab" to "СТЕНД",
        "lab.copy" to "КОПИЯ",
        "lab.title" to "УЧЕБНЫЙ СТЕНД",
        "lab.intro" to "Локальная, намеренно уязвимая площадка, чтобы законно тренироваться " +
            "инструментами безопасности — она работает на твоей машине, по твоим же мишеням.",
        "lab.warn.title" to "ТОЛЬКО ТВОЯ МАШИНА",
        "lab.warn.body" to "Стенд снимает вопрос законности: по этим контейнерам можно запускать " +
            "любые инструменты, даже агрессивные, потому что они твои. Никогда не направляй те же " +
            "инструменты на системы, которыми не владеешь или на проверку которых нет разрешения.",
        "lab.public.title" to "ЗА ПРЕДЕЛАМИ LOCALHOST (РАЗРЕШЁННЫЕ МИШЕНИ)",
        "lab.public.body" to "Вкладка «Аудит» уже сканирует любой введённый сайт. Для активной " +
            "практики вне своего устройства используй мишени, владельцы которых публично разрешают " +
            "тестирование — список ниже. Не направляй активные инструменты на другие чужие сайты.",
        "lab.phone.title" to "ТОЛЬКО ТЕЛЕФОН (TERMUX)",
        "lab.phone.body" to "ПК не нужен. Поставь Termux (из F-Droid) и выполни это — скачается и " +
            "запустится DSVW (Damn Small Vulnerable Web, готовый проект от stamparm) прямо на " +
            "телефоне. Он работает на localhost:65412 — просканируй его на вкладке «Аудит». " +
            "Полные шаги: lab/termux/README.md.",
        "lab.docker.title" to "ПОЛНЫЙ СТЕНД (НУЖЕН ПК)",
        "lab.docker.body" to "На машине с Docker можно поднять полноценные Juice Shop и DVWA и " +
            "навести на них настоящие Kali-инструменты.",
        "lab.step1.title" to "1 · ЗАПУСТИТЬ СТЕНД",
        "lab.step1.body" to "Нужен Docker. Поднимает OWASP Juice Shop и DVWA только на localhost.",
        "lab.targets.title" to "2 · ЛОКАЛЬНЫЕ МИШЕНИ",
        "lab.targets.body" to "Открой их в браузере или укажи localhost:3000 на вкладке «Аудит».",
        "lab.step2.title" to "3 · ЗАПУСК ИНСТРУМЕНТОВ ПО LOCALHOST",
        "lab.step2.body" to "На своей Kali-машине направляй наступательные инструменты на свои же " +
            "контейнеры.",
        "lab.step3.title" to "4 · РАЗБИРАТЬ УЯЗВИМОСТИ",
        "lab.step3.body" to "Инструменты — простая часть; эти ресурсы объясняют сами уязвимости.",
        "ui.lang.label" to "ЯЗЫК",
        "ui.footer" to "Приложение читает только то, что сайт сам о себе публикует: один запрос " +
            "страницы, TLS-пробы без передачи данных и политику раскрытия. Используйте его " +
            "только на системах, которыми владеете или на проверку которых есть разрешение.",
        "ui.error.title" to "ЗАПРОС НЕ ПРОШЁЛ",
        "ui.err.noTarget" to "Сначала введите адрес сайта.",
        "ui.err.generic" to "Запрос не удался.",

        // ---------------------------------------------------------------- report
        "ui.case.title" to "КРАТКО ПО ДЕЛУ",
        "ui.evidence" to "УЛИКИ",
        "ui.fix" to "Как исправить: %s",
        "ui.meta" to "HTTP %d · %d мс · наблюдений: %d",
        "ui.score" to "Гигиена заголовков: %d/100",
        "ui.sec.investigation" to "РАССЛЕДОВАНИЕ",
        "ui.sec.tech" to "ТЕХНОЛОГИЧЕСКИЙ ПРОФИЛЬ",
        "ui.sec.tls" to "TLS",
        "ui.sec.disclosure" to "ПОЛИТИКА РАСКРЫТИЯ",
        "ui.sec.observations" to "НАБЛЮДЕНИЯ",
        "ui.tech.stack" to "ВЫЧИСЛЕННЫЙ СТЕК",
        "ui.tech.signals" to "СИГНАЛЫ, ИЗ КОТОРЫХ ЭТО СЛЕДУЕТ",

        "ui.tls.accepted" to "ПРИНИМАЕТ",
        "ui.tls.refused" to "ОТКЛОНЯЕТ",
        "ui.tls.untestable" to "НЕЛЬЗЯ ПРОВЕРИТЬ ЗДЕСЬ",
        "ui.tls.suite" to "ШИФРНАБОР",
        "ui.tls.cert" to "СЕРТИФИКАТ",
        "ui.tls.issuer" to "КЕМ ВЫДАН",
        "ui.tls.expiresIn" to "ДЕЙСТВУЕТ ЕЩЁ",
        "ui.tls.sans" to "ЗАПИСЕЙ SAN",
        "ui.tls.unavailable" to "НЕ УДАЛОСЬ СНЯТЬ TLS-ПРОФИЛЬ",
        "ui.tls.nohandshake" to "Ни одно рукопожатие не состоялось.",
        "ui.tls.expiredAgo" to "истёк %d дн. назад",
        "ui.tls.daysLeft" to "%d дн.",

        "ui.stxt.missing.title" to "НЕ ОПУБЛИКОВАНА",
        "ui.stxt.missing.body" to "Ни по /.well-known/security.txt, ни по /security.txt " +
            "политики нет.",
        "ui.stxt.location" to "АДРЕС",
        "ui.stxt.contact" to "КОНТАКТ",
        "ui.stxt.expires" to "ДЕЙСТВУЕТ ДО",
        "ui.stxt.expiredSuffix" to "%s (просрочена)",
        "ui.stxt.policy" to "ПОЛИТИКА",
        "ui.stxt.encryption" to "ШИФРОВАНИЕ",
        "ui.stxt.languages" to "ЯЗЫКИ",
        "ui.stxt.canonical" to "КАНОНИЧЕСКИЙ АДРЕС",

        // ------------------------------------------------------------- vocabulary
        "sev.high" to "ВЫСОКИЙ",
        "sev.medium" to "СРЕДНИЙ",
        "sev.low" to "НИЗКИЙ",
        "sev.info" to "ИНФО",
        "conf.high" to "УВЕРЕННО",
        "conf.medium" to "ВЕРОЯТНО",
        "conf.low" to "ПРЕДПОЛОЖИТЕЛЬНО",
        "cat.transport" to "ТРАНСПОРТ",
        "cat.headers" to "ЗАГОЛОВКИ",
        "cat.cookies" to "COOKIE",
        "cat.tls" to "TLS",
        "cat.dns" to "DNS",
        "cat.content" to "КОНТЕНТ",
        "cat.disclosure" to "РАСКРЫТИЕ",
        "cat.general" to "ОБЩЕЕ",

        // -------------------------------------------------------- grade & words
        "ui.grade" to "ОЦЕНКА",
        "word.yes" to "да",
        "word.no" to "нет",

        // ----------------------------------------------------- new UI sections
        "prog.dns" to "Запрашиваю DNS-записи для %s …",
        "ui.sec.dns" to "DNS",
        "ui.dns.unavailable" to "НЕ УДАЛОСЬ ПОЛУЧИТЬ DNS",
        "ui.dns.caa" to "CAA",
        "ui.dns.dnssec" to "DNSSEC",
        "ui.dns.spf" to "SPF",
        "ui.dns.dmarc" to "DMARC",
        "ui.tls.key" to "ОТКРЫТЫЙ КЛЮЧ",
        "ui.tls.sig" to "ПОДПИСЬ",
        "ui.tls.chain" to "ДЛИНА ЦЕПОЧКИ",
        "ui.tls.covers" to "ПОКРЫВАЕТ ХОСТ",

        // -------------------------------------------------- certificate findings
        "f.certweaksig.title" to "Слабая подпись сертификата",
        "f.certweaksig.detail" to "Сертификат подписан алгоритмом %s, который опирается на " +
            "взломанную (коллизии) хеш-функцию.",
        "f.certweaksig.fix" to "Перевыпустите сертификат с подписью SHA-256 или сильнее.",

        "f.certweakkey.title" to "Слабый ключ сертификата",
        "f.certweakkey.detail" to "Сертификат использует ключ %s всего в %d бит.",
        "f.certweakkey.fix" to "Используйте минимум RSA 2048 или ключ EC P-256.",

        "f.certnohost.title" to "Хост не указан в сертификате",
        "f.certnohost.detail" to "SAN-записи предъявленного сертификата не покрывают " +
            "запрошенный хост. Браузер отклонил бы такой сертификат.",
        "f.certnohost.fix" to "Выпустите сертификат, в SAN которого есть этот хост.",

        "f.tlsprofile.key" to "Ключ: %s %d бит. ",
        "f.tlsprofile.sig" to "Подпись: %s. ",
        "f.tlsprofile.chain" to "Длина цепочки: %d. ",

        // ------------------------------------------------------- mixed content
        "f.mixed.title" to "Смешанный контент: %d ресурс(ов) по HTTP",
        "f.mixed.detail" to "Эта HTTPS-страница подключает ресурсы по http://:\n%s",
        "f.mixed.fix" to "Загружайте все подресурсы по https:// (или через protocol-relative URL).",

        // ----------------------------------------------------------- DNS findings
        "f.nocaa.title" to "Нет записи CAA",
        "f.nocaa.detail" to "Нет записи Certification Authority Authorization. Сертификат для " +
            "домена может выпустить любой УЦ.",
        "f.nocaa.fix" to "Опубликуйте запись CAA с разрешёнными удостоверяющими центрами.",

        "f.nodnssec.title" to "DNSSEC не включён",
        "f.nodnssec.detail" to "Ответы не аутентифицированы DNSSEC, поэтому DNS-ответы можно " +
            "подделать.",
        "f.nodnssec.fix" to "Включите подпись DNSSEC у вашего DNS-провайдера.",

        "f.nodmarc.title" to "Нет политики DMARC",
        "f.nodmarc.detail" to "Нет записи _dmarc. Злоумышленники могут подделывать почту от " +
            "имени домена.",
        "f.nodmarc.fix" to "Опубликуйте запись DMARC, двигаясь к p=reject.",

        "f.dmarcnone.title" to "Политика DMARC — p=none",
        "f.dmarcnone.detail" to "DMARC опубликован, но только наблюдает и не блокирует " +
            "поддельную почту.",
        "f.dmarcnone.fix" to "Переведите политику на quarantine, затем на reject.",

        "f.nospf.title" to "Нет записи SPF",
        "f.nospf.detail" to "Нет TXT-записи v=spf1. Получатели не могут проверить, какие хосты " +
            "вправе слать почту от домена.",
        "f.nospf.fix" to "Опубликуйте запись SPF с вашими легитимными отправителями.",

        "f.dnsprofile.title" to "Профиль DNS",
        "f.dnsprofile.caa" to "Записей CAA: %d. ",
        "f.dnsprofile.dnssec" to "DNSSEC: %s. ",
        "f.dnsprofile.spf" to "SPF: %s. ",
        "f.dnsprofile.dmarc" to "DMARC: %s.",

        // ------------------------------------------------- deep header hardening
        "f.cspinline.title" to "CSP разрешает 'unsafe-inline'",
        "f.cspinline.detail" to "Content-Security-Policy допускает inline-скрипты/стили, что почти " +
            "полностью сводит на нет защиту CSP от XSS.",
        "f.cspinline.fix" to "Убери 'unsafe-inline'; используй nonce или хеши.",

        "f.cspeval.title" to "CSP разрешает 'unsafe-eval'",
        "f.cspeval.detail" to "'unsafe-eval' позволяет исполнять строки как код (eval, new Function).",
        "f.cspeval.fix" to "Убери 'unsafe-eval' и перепиши код, которому он нужен.",

        "f.cspwildcard.title" to "CSP использует источник-звёздочку",
        "f.cspwildcard.detail" to "В default-src или script-src есть '*' — скрипты разрешены с " +
            "любого источника.",
        "f.cspwildcard.fix" to "Замени '*' на явный список доверенных источников.",

        "f.cspbaseuri.title" to "В CSP нет base-uri",
        "f.cspbaseuri.detail" to "Без base-uri внедрённый тег <base> может перехватить относительные " +
            "URL.",
        "f.cspbaseuri.fix" to "Добавь base-uri 'self' (или 'none').",

        "f.hstsshort.title" to "Короткий max-age у HSTS",
        "f.hstsshort.detail" to "max-age = %d сек.; меньше ~6 месяцев ослабляет гарантию и мешает " +
            "попасть в preload.",
        "f.hstsshort.fix" to "Ставь max-age=31536000 (1 год).",

        "f.hstsnosub.title" to "HSTS без includeSubDomains",
        "f.hstsnosub.detail" to "Поддомены не покрыты политикой HSTS.",
        "f.hstsnosub.fix" to "Добавь includeSubDomains (и preload, когда будешь готов).",

        "f.corscred.title" to "CORS отдаёт учётные данные конкретному источнику",
        "f.corscred.detail" to "Access-Control-Allow-Origin = «%s» вместе с Allow-Credentials: " +
            "true. Если этот источник отражается из запроса, любой сайт сможет читать " +
            "аутентифицированные ответы.",
        "f.corscred.fix" to "Никогда не сочетай credentials с отражённым/широким источником; укажи точный доверенный источник.",

        "f.corswildcard.title" to "CORS разрешает любой источник (*)",
        "f.corswildcard.detail" to "Access-Control-Allow-Origin: * позволяет любому сайту читать " +
            "ответ.",
        "f.corswildcard.fix" to "Ограничь конкретными доверенными источниками, если данные не публичные.",

        "f.cookiehost.title" to "Cookie «%s» нарушает правила __Host-",
        "f.cookiehost.detail" to "Cookie с префиксом __Host- должна быть Secure, Path=/ и без Domain.",
        "f.cookiehost.fix" to "Поставь Secure; Path=/ и убери атрибут Domain.",

        "f.cookiesecpfx.title" to "Cookie «%s» игнорирует свой префикс __Secure-",
        "f.cookiesecpfx.detail" to "Cookie с префиксом __Secure- обязана иметь атрибут Secure.",
        "f.cookiesecpfx.fix" to "Добавь атрибут Secure.",

        "f.cookiesamenone.title" to "Cookie «%s» с SameSite=None без Secure",
        "f.cookiesamenone.detail" to "SameSite=None требует Secure; иначе браузеры её отклоняют.",
        "f.cookiesamenone.fix" to "Добавь Secure или используй SameSite=Lax/Strict.",

        "f.hpkp.title" to "Устаревший заголовок Public-Key-Pins",
        "f.hpkp.detail" to "HPKP устарел и удалён из браузеров; ошибочный pin может заблокировать " +
            "доступ твоим же пользователям.",
        "f.hpkp.fix" to "Удали заголовок Public-Key-Pins.",

        "f.xxss.title" to "Включён X-XSS-Protection",
        "f.xxss.detail" to "Устаревший XSS-аудитор удалён из современных браузеров и может вносить " +
            "баги; значение должно быть 0 или отсутствовать.",
        "f.xxss.fix" to "Поставь X-XSS-Protection: 0 (полагайся на CSP).",

        // --------------------------------------------------------------- progress
        "prog.start" to "Запуск …",
        "prog.request" to "Запрашиваю %s …",
        "prog.tls" to "Проверяю версии TLS на %s …",
        "prog.stxt" to "Ищу политику раскрытия …",
        "prog.correlate" to "Связываю наблюдения …",

        // --------------------------------------------------------------- findings
        "f.info.fix" to "Справочно.",

        "f.nohttps.title" to "Сайт отдаётся не по HTTPS",
        "f.nohttps.detail" to "Итоговый ответ пришёл по обычному HTTP (%s). Трафик можно " +
            "прочитать или подменить по дороге.",
        "f.nohttps.fix" to "Отдавайте весь контент по HTTPS и перенаправляйте HTTP на HTTPS.",

        "f.hsts.title" to "Нет Strict-Transport-Security (HSTS)",
        "f.hsts.detail" to "Заголовка HSTS нет. При первом заходе браузер может уйти на HTTP.",
        "f.hsts.fix" to "Добавьте: Strict-Transport-Security: max-age=31536000; includeSubDomains",

        "f.csp.title" to "Нет Content-Security-Policy",
        "f.csp.detail" to "Заголовка CSP нет. CSP — одна из главных защит от XSS и внедрения данных.",
        "f.csp.fix" to "Опишите Content-Security-Policy под свои ресурсы.",

        "f.frame.title" to "Нет защиты от кликджекинга",
        "f.frame.detail" to "Нет ни X-Frame-Options, ни директивы frame-ancestors в CSP.",
        "f.frame.fix" to "Добавьте X-Frame-Options: DENY или директиву frame-ancestors в CSP.",

        "f.nosniff.title" to "Не отключено угадывание MIME-типа",
        "f.nosniff.detail" to "Отсутствует X-Content-Type-Options: nosniff.",
        "f.nosniff.fix" to "Добавьте: X-Content-Type-Options: nosniff",

        "f.referrer.title" to "Нет Referrer-Policy",
        "f.referrer.detail" to "Без Referrer-Policy полные адреса страниц могут утекать третьим " +
            "сторонам.",
        "f.referrer.fix" to "Добавьте: Referrer-Policy: strict-origin-when-cross-origin",

        "f.permissions.title" to "Нет Permissions-Policy",
        "f.permissions.detail" to "Permissions-Policy позволяет отключить мощные возможности " +
            "браузера.",
        "f.permissions.fix" to "Ограничьте ненужное, например geolocation=(), camera=().",

        "f.server.title" to "Раскрыта версия сервера",
        "f.server.detail" to "Заголовок Server выдаёт ПО и версию: «%s».",
        "f.server.fix" to "Уберите версию из заголовка Server.",

        "f.powered.title" to "Раскрыт X-Powered-By",
        "f.powered.detail" to "X-Powered-By выдаёт технологию бэкенда: «%s».",
        "f.powered.fix" to "Удалите заголовок X-Powered-By.",

        "f.cookie.title" to "У cookie «%s» слабые атрибуты",
        "f.cookie.detail" to "Cookie выставлена так: %s.",
        "f.cookie.fix" to "Ставьте Secure; HttpOnly; SameSite на сессионные cookie.",
        "f.cookie.issue.secure" to "нет Secure",
        "f.cookie.issue.httponly" to "нет HttpOnly",
        "f.cookie.issue.samesite" to "нет SameSite",

        "f.tlsfail.title" to "Не удалось снять профиль TLS",
        "f.tlsfail.fix" to "Проверьте хост из сети, где разрешены прямые TLS-соединения.",

        "f.tlsdeprecated.title" to "Принимается устаревший TLS: %s",
        "f.tlsdeprecated.detail" to "Сервер завершил рукопожатие по %s. Обе версии объявлены " +
            "устаревшими в RFC 8996 и отклоняются современными браузерами.",
        "f.tlsdeprecated.fix" to "Поставьте минимальную версию протокола TLS 1.2.",

        "f.notls13.title" to "TLS 1.3 не предлагается",
        "f.notls13.detail" to "Принимаемые версии: %s. TLS 1.3 убирает устаревшие примитивы и " +
            "укорачивает рукопожатие.",
        "f.notls13.fix" to "Включите TLS 1.3 на слушателе.",

        "f.certexpired.title" to "Сертификат истёк",
        "f.certexpired.detail" to "Предъявленный сертификат истёк %d дн. назад.",
        "f.certexpired.fix" to "Перевыпустите сертификат и проверьте автопродление.",

        "f.certexpiring.title" to "Сертификат истекает через %d дн.",
        "f.certexpiring.detail" to "Кем выдан: %s.",
        "f.certexpiring.fix" to "Убедитесь, что автопродление действительно работает.",

        "f.tlsprofile.title" to "Профиль TLS",
        "f.tlsprofile.accepted" to "Принимает: %s. ",
        "f.tlsprofile.refused" to "Отклоняет: %s. ",
        "f.tlsprofile.untestable" to "Нельзя проверить на этом устройстве: %s. ",
        "f.tlsprofile.suite" to "Согласованный шифрнабор: %s. ",
        "f.tlsprofile.subject" to "Субъект: %s. ",
        "f.tlsprofile.sans" to "Записей SAN: %d.",

        "f.nostxt.title" to "security.txt не опубликован",
        "f.nostxt.detail" to "Ни /.well-known/security.txt, ни /security.txt не вернули " +
            "политику. RFC 9116 вводит этот файл, чтобы исследователи знали, куда отправлять " +
            "сообщения об уязвимостях.",
        "f.nostxt.fix" to "Опубликуйте /.well-known/security.txt с полями Contact и Expires.",

        "f.stxtnocontact.title" to "В security.txt нет поля Contact",
        "f.stxtnocontact.detail" to "RFC 9116 требует хотя бы одно поле Contact, но в " +
            "опубликованном файле его нет.",
        "f.stxtnocontact.fix" to "Добавьте поле Contact (URI вида mailto:, https: или tel:).",

        "f.stxtexpired.title" to "security.txt просрочен",
        "f.stxtexpired.detail" to "В поле Expires указано %s — это в прошлом. Клиенты должны " +
            "игнорировать просроченную политику.",
        "f.stxtexpired.fix" to "Обновите Expires (RFC 9116 советует срок меньше года).",

        "f.stxtnoexpires.title" to "В security.txt нет поля Expires",
        "f.stxtnoexpires.detail" to "По RFC 9116 поле Expires обязательно.",
        "f.stxtnoexpires.fix" to "Добавьте метку времени Expires в формате ISO-8601.",

        "f.stxtbadexpires.title" to "Значение Expires в security.txt не разбирается",
        "f.stxtbadexpires.detail" to "Не удалось прочитать «%s» как метку времени ISO-8601.",
        "f.stxtbadexpires.fix" to "Используйте формат вида 2027-01-01T00:00:00.000Z.",

        "f.stxtok.title" to "security.txt опубликован",
        "f.stxtok.detail" to "Найден по адресу %s. Контакт: %s. Действует до %s.",
        "f.stxtok.policy" to " Политика: %s.",

        // ------------------------------------------------------------------ leads
        "l.unmaintained.h" to "Похоже, этот сервер давно никто не обслуживает",
        "l.unmaintained.s" to "Независимые сигналы сходятся на стареющей конфигурации. Важны не " +
            "столько отдельные пункты, сколько сам рисунок: владелец хоста, скорее всего, не " +
            "применяет текущие рекомендации вендора — значит, и другие обновления, вероятно, " +
            "не установлены. Проверьте уровень патчей платформы напрямую.",

        "l.cookiechain.h" to "Эти cookie могут уйти по сети в открытом виде",
        "l.cookiechain.s.hsts" to "HSTS удерживает браузер на HTTPS после первого визита, и это " +
            "сильно сужает проблему, но сами cookie всё равно без Secure. Всё, что попадёт на " +
            "сайт по HTTP до того, как политика закешируется, или придёт от клиента, который её " +
            "игнорирует, отправит их незащищёнными. Поставьте Secure в любом случае.",
        "l.cookiechain.s.nohsts" to "Здесь складываются две дыры. Без Secure браузер готов " +
            "отправить эти cookie по обычному HTTP, а без HSTS ничто не мешает ему такой " +
            "HTTP-запрос сделать. Вместе это означает, что значения сессии может увидеть любой " +
            "на сетевом пути. Починка любой одной дыры разрывает цепочку; почините обе.",

        "l.hardening.h" to "Слой защитных заголовков здесь вообще не настраивали",
        "l.hardening.s" to "Когда не хватает одного-двух заголовков, за этим обычно стоит " +
            "осознанный компромисс. Когда отсутствуют сразу %d, это почти всегда значит, что " +
            "заголовками ответа никто не занимался и сервер отвечает настройками по умолчанию. " +
            "Это стоит разобрать как пробел в процессе, а не только в конфиге: тот же пропуск, " +
            "скорее всего, касается и других хостов.",

        "l.edgeleak.h" to "CDN закрывает сайт, но отпечаток origin-сервера проходит насквозь",
        "l.edgeleak.s" to "Смысл пограничного слоя в том числе и в том, чтобы ПО origin-сервера " +
            "не было делом всего интернета. Эти заголовки и имена cookie формируются за CDN и " +
            "передаются без изменений, то есть абстракция протекает. Вырезайте заголовки, " +
            "идентифицирующие origin, на границе или на самом сервере.",

        "l.fingerprint.h" to "Стек легко определить, и при этом некуда сообщить о проблеме",
        "l.fingerprint.s" to "Эти два факта интересны только вместе. То, что стек определяется, " +
            "нормально и почти безвредно. Проблема в асимметрии: исследователю, который " +
            "заметит неладное, некуда об этом написать — и сообщение либо пропадёт, либо " +
            "выйдет в публичное поле. Опубликовать security.txt по RFC 9116 с рабочим " +
            "контактом стоит очень дёшево.",

        "l.cert.h.expired" to "Сертификат уже просрочен",
        "l.cert.h.expiring" to "Сертификат скоро истекает",
        "l.cert.s" to "Перевыпуск — рутина, поэтому короткий остаток срока говорит прежде всего " +
            "об автоматизации: либо продление автоматическое и всё в порядке, либо оно ручное " +
            "и однажды его пропустят. Проверьте, действительно ли работает ACME-продление, а не " +
            "просто продлите руками в этот раз.",

        "l.downgrade.h" to "Современный TLS есть, но устаревшие версии так и не выключили",
        "l.downgrade.s" to "Раз современные клиенты и так договариваются на сильную версию, " +
            "включённые TLS 1.0/1.1 почти не дают реальной совместимости, зато оставляют " +
            "доступными слабости старых протоколов. Обычно такой рисунок означает, что конфиг " +
            "обновляли добавлением новых версий, а не заменой списка. Поставьте минимум TLS 1.2.",

        "l.weakcipher.h" to "Согласованный шифрнабор построен на устаревших примитивах",
        "l.weakcipher.s" to "Это то, что сервер выбрал сам при разговоре с этим устройством, то " +
            "есть дело в порядке предпочтений, а не только в списке поддерживаемого. Ставьте " +
            "вперёд AEAD-наборы (GCM или ChaCha20-Poly1305).",

        // ------------------------------------------------------------------ clues
        "c.legacyHandshake" to "Сервер завершает рукопожатие по %s",
        "c.bannerOutdated" to "Баннер сообщает %s",
        "c.stxtExpired" to "Опубликованный security.txt просрочен с %s",
        "c.noTls13" to "TLS 1.3 не предлагается",
        "c.servedHttps" to "Сайт отдаётся по HTTPS",
        "c.cookiesNoSecure" to "Cookie выставлены без атрибута Secure: %s",
        "c.noHstsPolicy" to "Политика Strict-Transport-Security не публикуется",
        "c.legacyStillAccepted" to "Устаревший TLS (%s) всё ещё принимается",
        "c.headerAbsent" to "Нет %s",
        "c.edgeServing" to "Ответ отдаёт %s",
        "c.poweredByReports" to "X-Powered-By по-прежнему сообщает «%s»",
        "c.aspnetVersion" to "X-AspNet-Version сообщает «%s»",
        "c.originCookie" to "Cookie фреймворка origin-сервера «%s» проходит через границу",
        "c.identifiedStack" to "Определено по метаданным ответа: %s",
        "c.noStxtFile" to "Нет security.txt ни по /.well-known/security.txt, ни по /security.txt",
        "c.stxtNoContactField" to "security.txt есть, но поля Contact в нём нет",
        "c.certExpiredAgo" to "Сертификат истёк %d дн. назад",
        "c.certExpiresIn" to "Сертификат истекает через %d дн.",
        "c.issuedBy" to "Выдан: %s",
        "c.noSecurityContact" to "Опубликованного контакта по безопасности нет — некого известить",
        "c.acceptedVersions" to "Принимает: %s",
        "c.deprecatedNegotiated" to "Устаревшие версии всё ещё согласуются: %s",
        "c.modernClientUses" to "Современный клиент будет использовать %s",
        "c.negotiatedSuite" to "Согласованный шифрнабор: %s",
        "c.datedElements" to "Устаревшие элементы: %s",

        "hdr.csp" to "Content-Security-Policy",
        "hdr.frame" to "защиты от фреймов",
        "hdr.nosniff" to "X-Content-Type-Options",
        "hdr.referrer" to "Referrer-Policy",
        "hdr.permissions" to "Permissions-Policy",

        // ------------------------------------------------------------------- tech
        "tech.branchNote" to "%s %s (поддерживаемая ветка начинается с %s)",
        "tech.src.server" to "Заголовок Server",
        "tech.src.powered" to "Заголовок X-Powered-By",
        "tech.src.cookie" to "Имя cookie",
        "tech.src.link" to "Заголовок Link",
        "tech.src.header" to "Заголовок %s",
        "tech.linkWpJson" to "REST-маршрут wp-json",
        "tech.unrecognised" to "строка продукта не распознана",
        "tech.cdnInFront" to "%s перед origin-сервером",
        "tech.cmsGenerator" to "генератор CMS",
        "tech.javaServlet" to "контейнер сервлетов Java",
        "tech.present" to "присутствует",

        // -------------------------------------------------------------- narration
        "narr.nothing" to "В собранных метаданных ничто не противоречит друг другу, и ни одно " +
            "сочетание наблюдений не сложилось в цепочку, о которой стоило бы сообщить. Это " +
            "утверждение только о пассивных сигналах — оно не означает, что с приложением за " +
            "ними всё в порядке.",
        "narr.opening" to "Изучен %s по %s",
        "narr.stack" to ", который выглядит как %s",
        "narr.top" to "Ниточка, за которую стоит потянуть в первую очередь: %s (%s, собрано из " +
            "%d наблюдений). ",
        "narr.multiHigh" to "Высокую критичность дали %d независимые цепочки — обычно это " +
            "указывает на одну общую причину, а не на несколько разных. ",
        "narr.closing" to "У каждого вывода ниже перечислены улики — проверьте рассуждение, " +
            "прежде чем действовать.",
        "narr.protoHttp" to "HTTP",

        // ---------------------------------------------------------------- AI (Gemini)
        "ai.lang" to "русском",
        "ai.prompt" to "Ты помощник по веб-безопасности. На %s языке объясни простыми словами для " +
            "владельца сайта эту находку аудита: что это значит, почему важно и как исправить. " +
            "Кратко (3–5 предложений), без markdown. Находка: «%s». Детали: %s. Как исправить: %s.",
        "ai.title" to "ИИ-ОБЪЯСНЕНИЯ (GEMINI)",
        "ai.key.hint" to "Вставь свой ключ Gemini API",
        "ai.save" to "СОХРАНИТЬ",
        "ai.saved" to "Ключ сохранён — у каждой находки теперь есть кнопка ИИ.",
        "ai.get" to "Бесплатный ключ: aistudio.google.com",
        "ai.explain" to "ОБЪЯСНИТЬ (AI)",
        "ai.explainAll" to "ОБЪЯСНИТЬ ВСЁ (AI)",
        "ai.prompt.all" to "Ты помощник по веб-безопасности. На %s языке объясни владельцу сайта " +
            "весь этот аудит %s (оценка %s, балл %d/100): кратко о главных проблемах, почему они " +
            "важны и что чинить в первую очередь. Простыми словами, без markdown, группируй " +
            "похожее. Находки:\n%s",
        "ai.explaining" to "Спрашиваю Gemini …",
        "ai.needkey" to "Добавь ключ Gemini на вкладке «Аудит», чтобы включить ИИ-объяснения."
    )
}
