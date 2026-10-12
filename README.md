# Gateway

Spring Cloud Gateway (WebFlux) в роли BFF: аутентификация пользователей через Keycloak, Token Relay и Rate Limiter.

## Зона ответственности Gateway

- аутентификация пользователя через Keycloak (Authorization Code + PKCE), сессия с токенами хранится в Redis, браузеру отдаётся только cookie;
- Token Relay: access token подставляется в `Authorization: Bearer` при проксировании в микросервисы, обновление по refresh token;
- Rate Limiter (Redis, token bucket): ключ - пользователь, для анонимов - IP.

Авторизация (проверка ролей и прав) в Gateway не выполняется: её делают микросервисы по JWT Keycloak.

## Вне объёма Gateway

- Управление ролями и пользователями. Выполняется в консоли Keycloak либо отдельным сервисом через Keycloak Admin REST API (сервисный аккаунт с ролями `realm-management`). В Gateway такие эндпоинты не размещаются.
- Подключение микросервисов как resource server (валидация JWT по JWKS Keycloak).
