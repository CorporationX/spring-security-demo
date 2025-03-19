package school.faang.springsecuritydemo.auth;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/**
 * Конфигурация для создания и настройки BCryptPasswordEncoder.
 * <p>
 * Этот класс используется для конфигурации бина BCryptPasswordEncoder, который будет
 * использоваться для хеширования паролей в приложении с использованием алгоритма BCrypt.
 * <p>
 * Алгоритм BCrypt является безопасным методом хеширования паролей, с использованием соли,
 * и позволяет настроить количество итераций для повышения безопасности.
 */
@Configuration
public class PasswordEncoderConfig {

    /**
     * Создает бин BCryptPasswordEncoder с заданным количеством итераций.
     *
     * @return новый экземпляр BCryptPasswordEncoder с 12 итерациями.
     * Количество итераций (12) отвечает за сложность хеширования: чем больше значение,
     * тем безопаснее, но и более ресурсоемко.
     */
    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }
}
