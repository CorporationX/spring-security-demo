package school.faang.springsecuritydemo.auth;

import java.util.Collection;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

/**
 * Класс, реализующий интерфейс UserDetails, представляющий информацию о пользователе для Spring Security.
 * <p>
 * Этот класс используется для хранения и предоставления информации о пользователе, такой как имя,
 * пароль и права доступа (роли). Он является частью системы аутентификации и авторизации в приложении,
 * обеспечивая взаимодействие с механизмами безопасности Spring Security.
 */
@Getter
public class CustomUserDetails implements UserDetails {

    /**
     * Уникальный идентификатор пользователя
     * */
    private final Long id;

    /**
     * Имя пользователя (логин)
     * */
    private final String username;

    /**
     * Пароль пользователя
     * */
    private final String password;

    /**
     * Коллекция авторизационных данных пользователя (например, роли, права доступа)
     * */
    private final Collection<? extends GrantedAuthority> authorities;

    /**
     * Конструктор для инициализации объекта CustomUserDetails.
     *
     * @param id Уникальный идентификатор пользователя.
     * @param username Имя пользователя (логин).
     * @param password Пароль пользователя.
     * @param authorities Коллекция авторизационных данных пользователя (роли, права).
     */
    public CustomUserDetails(Long id,
                             String username,
                             String password,
                             Collection<? extends GrantedAuthority> authorities) {
        this.id = id;
        this.username = username;
        this.password = password;
        this.authorities = authorities;
    }
}
