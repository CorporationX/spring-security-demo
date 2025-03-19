package school.faang.springsecuritydemo.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import school.faang.springsecuritydemo.auth.SecurityConstants;

/**
 * Утилитный класс для работы с JWT (JSON Web Token).
 * <p>
 * Этот класс предоставляет методы для создания, извлечения и декодирования JWT токенов
 * (как access, так и refresh токенов). Используется для генерации токенов аутентификации и извлечения информации из них.
 */
@Component
@RequiredArgsConstructor
public class JwtTokenUtils {

    // Константы безопасности, содержащие секреты и настройки для токенов
    private final SecurityConstants securityConstants;

    /**
     * Генерация access токена для пользователя.
     * <p>
     * Этот метод создает JWT access токен с использованием данных пользователя (например, его ролей),
     * а также с указанием времени действия токена, который берется из конфигурации.
     *
     * @param userDetails данные пользователя, для которого генерируется токен.
     * @return JWT токен доступа.
     */
    public String generateAccessToken(UserDetails userDetails) {
        // Сборка данных (claims), которые будут добавлены в токен
        Map<String, Object> claims = new HashMap<>();
        List<String> rolesList = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList();
        claims.put("roles", rolesList);

        // Установка времени создания и истечения токена
        Date issuedDate = new Date();
        Date expiredDate = new Date(issuedDate.getTime() + securityConstants.getAccessLifetime());

        // Создание и подпись JWT токена
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(userDetails.getUsername())  // Установка имени пользователя
                .setIssuedAt(issuedDate)  // Время создания токена
                .setExpiration(expiredDate)  // Время истечения токена
                .signWith(SignatureAlgorithm.HS256,
                        securityConstants.getAccessSecret())  // Подпись с использованием секрета
                .compact();  // Сборка токена
    }

    /**
     * Генерация refresh токена для пользователя.
     * <p>
     * Этот метод создает JWT refresh токен с аналогичной логикой, как и для access токена,
     * но с использованием другого времени жизни и секретного ключа для подписи.
     *
     * @param userDetails данные пользователя, для которого генерируется токен.
     * @return JWT refresh токен.
     */
    public String generateRefreshToken(UserDetails userDetails) {
        // Сборка данных (claims), которые будут добавлены в токен
        Map<String, Object> claims = new HashMap<>();
        List<String> rolesList = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList();
        claims.put("roles", rolesList);

        // Установка времени создания и истечения токена
        Date issuedDate = new Date();
        Date expiredDate = new Date(issuedDate.getTime() + securityConstants.getRefreshLifetime());

        // Создание и подпись JWT токена
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(userDetails.getUsername())  // Установка имени пользователя
                .setIssuedAt(issuedDate)  // Время создания токена
                .setExpiration(expiredDate)  // Время истечения токена
                .signWith(SignatureAlgorithm.HS256,
                        securityConstants.getRefreshSecret())  // Подпись с использованием секрета
                .compact();  // Сборка токена
    }

    /**
     * Извлечение имени пользователя из JWT токена.
     * <p>
     * Этот метод извлекает имя пользователя (subject) из токена, используя указанный секрет.
     *
     * @param token  JWT токен, из которого нужно извлечь имя пользователя.
     * @param secret секретный ключ, используемый для проверки подписи токена.
     * @return имя пользователя, содержащиеся в токене.
     */
    public String getUsername(String token, String secret) {
        return getAllClaimsFromToken(token, secret).getSubject();
    }

    /**
     * Извлечение ролей из JWT токена.
     * <p>
     * Этот метод извлекает список ролей (claims) из токена, используя указанный секрет.
     *
     * @param token  JWT токен, из которого нужно извлечь роли.
     * @param secret секретный ключ, используемый для проверки подписи токена.
     * @return список ролей пользователя, содержащихся в токене.
     */
    public List<String> getRoles(String token, String secret) {
        return getAllClaimsFromToken(token, secret).get("roles", List.class);
    }

    /**
     * Извлечение всех данных (claims) из JWT токена.
     * <p>
     * Этот метод разбирает токен и возвращает все claims, которые были в нем закодированы.
     *
     * @param token  JWT токен, из которого нужно извлечь claims.
     * @param secret секретный ключ, используемый для проверки подписи токена.
     * @return объект `Claims`, содержащий все данные из токена.
     */
    private Claims getAllClaimsFromToken(String token, String secret) {
        return Jwts.parser()
                .setSigningKey(secret)  // Установка секретного ключа для проверки подписи
                .parseClaimsJws(token)  // Разбор токена
                .getBody();  // Получение тела токена (claims)
    }
}
