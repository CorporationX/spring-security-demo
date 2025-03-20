# spring-security-demo

Демо-проект для митапа по Spring Security

# Практические задания

1. Практическое задание выполняется в отдельной ветке
2. Почковаться от `main`
3. PR создавать в `main`
4. В названии PR указать номера заданий, которые были выполнены
5. Можно создавать по одному PR на задание, можно сразу несколько заданий в одном PR
6. Задания считаются выполненными, когда все комментарии поправлены и PR закрыт (в `main` ничего не
   заливаем)

## Названия веток, коммитов и PR

1. Название ветки: `security-<ник_github>`
2. Название PR: `Практическое задание №1`, если несколько заданий в одном PR,
   то `Практическое задание №1, 2, 5`
3. Названия коммитов: `Осмысленные`

# 📌 Задание №1: Передача токенов в заголовках вместо DTO (🧠/5)

## 🔹 1. Цель

В текущей реализации токены (access и refresh) передаются в теле ответа (DTO). Необходимо изменить
подход, чтобы токены передавались через соответствующие HTTP-заголовки.

📌 **Токены должны передаваться в заголовках ответа вместо DTO**

## 🔹 2. Что нужно сделать?

### ✅ 2.1. Изменить способ передачи токенов в ответах

- Вместо того чтобы передавать токены в теле ответа (DTO), их необходимо отправлять в
  HTTP-заголовках. Например:
    - `Authorization: Bearer <access_token>`
    - `Refresh-Token: <refresh_token>`

---

# 📌 Задание №2: Разделение `UserService` и `UserDetailsService` (🧠/5)

## 🔹 1. Цель

В текущей реализации `UserService` выполняет сразу две задачи:

1. **Работу с пользователями (регистрация, поиск, получение текущего пользователя)**
2. **Загрузку пользователей для Spring Security (реализация `UserDetailsService`)**

📌 **Необходимо разделить эти обязанности, чтобы `UserService` занимался бизнес-логикой,
а `UserDetailsService` только загрузкой пользователей для аутентификации.**


## 🔹 2. Что нужно сделать?

### ✅ 2.1. Создать `CustomUserDetailsService`, который реализует `UserDetailsService`

- Перенести метод `loadUserByUsername()` из `UserService`.

### ✅ 2.2. Обновить `UserService`

- Удалить реализацию `UserDetailsService`.
- Оставить методы, относящиеся к
  бизнес-логике (`createNewUser()`, `findByUsername()`, `getCurrentUserInfo()`).

### ✅ 2.3. Обновить `SecurityConfig`

- Использовать `CustomUserDetailsService` как бин для аутентификации.

---

# 📌 Задание №3: Реализация logout с удалением refresh-токена (🧠🧠/5)

## 🔹 1. Цель

В текущей реализации при logout не происходит удаления refresh-токена. Необходимо реализовать
процесс logout, чтобы при выходе из системы refresh-токен удалялся, и пользователь больше не мог
использовать его для получения нового access-токена.

📌 **При выходе из системы refresh-токен должен удаляться, и сессия пользователя должна быть
завершена.**


## 🔹 2. Что нужно сделать?

### ✅ 2.1. Создать эндпоинт для logout

- Реализовать новый эндпоинт для logout, который будет удалять refresh-токен. Этот эндпоинт может
  быть доступен только для авторизованных пользователей.

---

# 📌 Задание №4: Перенос хранения refresh-токенов из PostgreSQL в Redis (🧠🧠🧠/5)

## 🔹 1. Цель

Сейчас refresh-токены хранятся в PostgreSQL. Необходимо **перенести их в Redis**, чтобы обеспечить:

- **Более быстрое чтение** (Redis работает в оперативной памяти).
- **Автоматическое удаление по TTL** (токены удаляются после истечения срока).
- **Масштабируемость** (легкость горизонтального масштабирования).

## 🔹 2. Что нужно сделать?

### ✅ 2.1. Отключить хранение refresh-токенов в PostgreSQL

- Удалить использование **JPA Repository** для токенов.
- Удалить JPA-сущность `RefreshToken` (если использовалась).
- Удалить код, связанный с сохранением, обновлением и удалением токенов в PostgreSQL.

### ✅ 2.2. Подключить Redis в Spring Boot

- Добавить зависимость `spring-boot-starter-data-redis` в `pom.xml`.
- Настроить подключение к Redis в `application.yml`.
- Создать сервис `RefreshTokenService` для работы с Redis.

### ✅ 2.3. Реализовать хранение refresh-токенов в Redis

- Сохранять токены в **Redis** с привязкой к **userId**.
- Устанавливать **TTL (например, 7 дней)**.
- Добавить методы для **создания, получения и удаления** refresh-токена.

### ✅ 2.4. Протестировать работу

- Проверить, что токены корректно записываются и извлекаются из Redis.
- Убедиться, что при выходе пользователя (`logout`) его токен удаляется.
- Проверить, что Redis сохраняет данные при перезапуске (если включена персистентность).

---

# 📌 Задание №5: Добавить создание Ролей и Привилегий для пользователя (🧠🧠🧠🧠/5)

## 🔹 1. Цель

Необходимо реализовать **механизм ролей и привилегий** в системе, чтобы управлять доступом
пользователей к различным ресурсам.

- **Роли (Roles)** – группы разрешений (например, `ADMIN`, `USER`).
- **Привилегии (Privileges)** – **жестко зашиты в коде** и не хранятся в БД.
- **Связь "многие ко многим"** между ролями и привилегиями.
- **Связь "многие ко многим"** между пользователями и ролями.
- **В `GrantedAuthorities` должны использоваться привилегии**.
- **Добавить тестовый контроллер для проверки `@PreAuthorize(hasAuthority)`**.

## 🔹 2. Что нужно сделать?

### ✅ 2.1. Создать `enum Privilege`

- Привилегии будут жестко заданы в коде и **не будут храниться в БД**.

### ✅ 2.2. Создать сущность `Role`

- Таблица `roles` (роль пользователя).
- Таблица `users_roles` (связь пользователей с ролями).

### ✅ 2.3. Создать JPA-репозиторий для ролей

- `RoleRepository`

### ✅ 2.4. Создать сервис `RoleService`

- Добавить методы для создания ролей (с привязанными к ним привилегиями).
- Добавить возможность назначения ролей пользователю.

### ✅ 2.5. **Обновить `CustomUserDetails` для работы с привилегиями**

- В `GrantedAuthorities` должны использоваться **привилегии** вместо ролей.

### ✅ 2.6. **Добавить тестовый контроллер для проверки `@PreAuthorize(hasAuthority)`**

Например, добавить возможность регистрации пользователя, а роли будет назначать администратор системы.
---

# 📌 Задание №6: Переход от секретных строк к ключам для JWT (🧠🧠🧠🧠🧠/5)

## 🔹 1. Цель

В текущей реализации JWT использует секретные строки для подписи и верификации токенов. Нужно
изменить подход, заменив секретные строки на пару ключей (приватный и публичный) для обеспечения
более высокой безопасности.

**Необходимо заменить строки секретов на пары ключей (RSA) для генерации и проверки JWT-токенов.**

---

## 🔹 2. Что нужно сделать?

### ✅ 2.1. Создать пару ключей (приватный и публичный)

- Сгенерировать пару ключей (приватный и публичный) для использования в подписи и верификации JWT.

### ✅ 2.2. Обновить конфигурацию для использования ключей

- Заменить строковые секреты в конфигурации на пути к сгенерированным приватному и публичному
  ключам.

### ✅ 2.3. Обновить код для использования ключей при генерации и верификации JWT

- Заменить использование строковых секретов на использование приватного и публичного ключей.

## 📌 3. Ожидаемый результат

JWT теперь будет подписываться с использованием приватного ключа и проверяться с использованием
публичного ключа.
Конфигурация больше не будет содержать секретных строк для JWT.
Повышение уровня безопасности токенов.

## 🤔 Подсказка

Код для генерации ключей (полученные значения нужно вставить в `application.yaml`)

```java
        Security.addProvider(new BouncyCastleProvider());

        KeyPairGenerator keyGen=KeyPairGenerator.getInstance("EC","BC");
        keyGen.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair keyPair=keyGen.generateKeyPair();

        byte[]privateKeyBytes=keyPair.getPrivate().getEncoded();
        String privateKeyBase64=Base64.getEncoder().encodeToString(privateKeyBytes);

        byte[]publicKeyBytes=keyPair.getPublic().getEncoded();
        String publicKeyBase64=Base64.getEncoder().encodeToString(publicKeyBytes);

        System.out.println("Private Key (PKCS8, Base64): "+privateKeyBase64);
        System.out.println("Public Key (X.509, Base64): "+publicKeyBase64);
```

