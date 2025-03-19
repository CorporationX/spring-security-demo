package school.faang.springsecuritydemo.service;

import java.util.Collection;
import java.util.List;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import school.faang.springsecuritydemo.auth.CustomUserDetails;
import school.faang.springsecuritydemo.domain.User;
import school.faang.springsecuritydemo.dto.request.RegistrationUserRequest;
import school.faang.springsecuritydemo.dto.response.CurrentUserResponse;
import school.faang.springsecuritydemo.repository.UserRepository;

/**
 * Сервис для работы с пользователями.
 * <p>
 * Этот сервис реализует интерфейс `UserDetailsService`, предоставляя метод для загрузки
 * пользователя по имени пользователя, а также методы для регистрации новых пользователей
 * и получения информации о текущем пользователе.
 */
@Service
@RequiredArgsConstructor
public class UserService implements UserDetailsService {

    // Репозиторий для работы с пользователями
    private final UserRepository userRepository;

    // Сервис для работы с ролями пользователей
    private final RoleService roleService;

    // Кодировщик паролей для безопасного хранения паролей
    private final PasswordEncoder passwordEncoder;

    /**
     * Загрузка пользователя по имени пользователя.
     * <p>
     * Этот метод загружает пользователя из базы данных по имени пользователя,
     * а также извлекает его роли и создает объект `CustomUserDetails`, который используется для аутентификации.
     *
     * @param username имя пользователя для поиска.
     * @return объект `CustomUserDetails` с данными о пользователе.
     * @throws UsernameNotFoundException если пользователь с таким именем не найден.
     */
    @Override
    @Transactional
    public CustomUserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // Поиск пользователя по имени
        User user = findByUsername(username).orElseThrow(() -> new UsernameNotFoundException(
                String.format("Пользователь '%s' не найден", username)
        ));

        // Преобразование ролей пользователя в список SimpleGrantedAuthority
        Collection<SimpleGrantedAuthority> authorities = user.getRoles().stream()
                .map(role -> new SimpleGrantedAuthority(role.getName()))
                .toList();

        // Возвращаем объект CustomUserDetails
        return new CustomUserDetails(
                user.getId(),
                user.getUsername(),
                user.getPassword(),
                authorities
        );
    }

    /**
     * Поиск пользователя по имени.
     * <p>
     * Этот метод возвращает пользователя, если он существует в базе данных,
     * или `Optional.empty()` в случае отсутствия пользователя.
     *
     * @param username имя пользователя для поиска.
     * @return `Optional<User>` с найденным пользователем или пустым значением, если пользователь не найден.
     */
    public Optional<User> findByUsername(String username) {
        return userRepository.findByUsername(username);
    }

    /**
     * Регистрация нового пользователя.
     * <p>
     * Этот метод создает нового пользователя, кодирует его пароль с использованием
     * `PasswordEncoder`, присваивает ему роль пользователя и сохраняет в базе данных.
     *
     * @param registrationUserRequest данные для регистрации нового пользователя.
     * @return сохраненный объект пользователя.
     */
    public User createNewUser(RegistrationUserRequest registrationUserRequest) {
        User user = new User();
        user.setUsername(registrationUserRequest.getUsername());
        user.setEmail(registrationUserRequest.getEmail());
        user.setPassword(passwordEncoder.encode(
                registrationUserRequest.getPassword()));  // Кодирование пароля
        user.setRoles(List.of(roleService.getUserRole()));  // Установка роли пользователя
        return userRepository.save(user);  // Сохранение пользователя в базу данных
    }

    /**
     * Получение информации о текущем пользователе.
     * <p>
     * Этот метод извлекает текущего аутентифицированного пользователя из контекста безопасности
     * и возвращает информацию о нем, такую как ID и имя пользователя.
     *
     * @return объект `CurrentUserResponse` с информацией о текущем пользователе.
     * @throws BadCredentialsException если не удается найти пользователя по имени.
     */
    public CurrentUserResponse getCurrentUserInfo() {
        // Получение текущего аутентифицированного пользователя
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        // Поиск пользователя по имени из контекста аутентификации
        var user = userRepository.findByUsername(authentication.getName()).orElseThrow(
                () -> new BadCredentialsException("Не удалось найти пользователя по имени"));

        // Возвращение данных о текущем пользователе
        return new CurrentUserResponse(user.getId(), user.getUsername());
    }
}

