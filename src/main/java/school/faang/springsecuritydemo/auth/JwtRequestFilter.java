package school.faang.springsecuritydemo.auth;

import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import school.faang.springsecuritydemo.util.JwtTokenUtils;

/**
 * Фильтр для обработки JWT-токенов в запросах.
 * <p>
 * Этот фильтр извлекает JWT-токен из заголовка авторизации запроса, проверяет его валидность
 * и, если токен действителен, извлекает имя пользователя и роли, добавляя их в контекст безопасности Spring Security.
 * Это необходимо для аутентификации и авторизации пользователя в приложении.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class JwtRequestFilter extends OncePerRequestFilter {

    /**
     * Утилиты для работы с JWT-токенами
     */
    private final JwtTokenUtils jwtTokenUtils;

    /**
     * Константы безопасности, включая имя заголовка и префикс "Bearer"
     */
    private final SecurityConstants securityConstants;


    /**
     * Метод, выполняющий фильтрацию запросов.
     * <p>
     * Извлекает JWT-токен из заголовка запроса, проверяет его валидность и извлекает информацию
     * о пользователе и его ролях. Если токен действителен, аутентифицирует пользователя в контексте Spring Security.
     *
     * @param request     HTTP-запрос.
     * @param response    HTTP-ответ.
     * @param filterChain Цепочка фильтров для передачи запроса дальше.
     * @throws ServletException В случае ошибок при фильтрации.
     * @throws IOException      В случае ошибок при обработке запроса.
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        var authHeader = request.getHeader(securityConstants.getAuthHeader());
        var bearerPrefix = securityConstants.getBearerPrefix();
        String username = null;
        String accessToken = null;
        if (authHeader != null && authHeader.startsWith(bearerPrefix)) {
            accessToken = authHeader.substring(bearerPrefix.length());
            try {
                username =
                        jwtTokenUtils.getUsername(accessToken, securityConstants.getAccessSecret());
            } catch (ExpiredJwtException e) {
                log.error("Время жизни токена истекло");
            } catch (SecurityException e) {
                log.error(e.getMessage());
            }
        }
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            var roles = jwtTokenUtils.getRoles(accessToken, securityConstants.getAccessSecret())
                    .stream()
                    .map(SimpleGrantedAuthority::new)
                    .toList();
            UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(
                    username, null, roles

            );
            SecurityContextHolder.getContext().setAuthentication(token);
        }
        filterChain.doFilter(request, response);
    }
}
