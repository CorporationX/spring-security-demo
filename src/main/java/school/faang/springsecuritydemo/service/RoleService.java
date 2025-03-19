package school.faang.springsecuritydemo.service;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import school.faang.springsecuritydemo.domain.Role;
import school.faang.springsecuritydemo.repository.RoleRepository;

@Service
@RequiredArgsConstructor
public class RoleService {
    private final RoleRepository roleRepository;

    public Role getUserRole() {
        return roleRepository.findByName("ROLE_USER").get();
    }
}
