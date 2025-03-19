package school.faang.springsecuritydemo.repository;

import org.springframework.data.repository.CrudRepository;
import school.faang.springsecuritydemo.domain.RefreshToken;

public interface RefreshTokenRepository extends CrudRepository<RefreshToken, Long> {

    boolean existsRefreshTokenByToken(String token);

    void deleteByToken(String token);

}
