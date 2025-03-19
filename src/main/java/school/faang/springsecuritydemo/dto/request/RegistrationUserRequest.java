package school.faang.springsecuritydemo.dto.request;

import lombok.Data;

@Data
public class RegistrationUserRequest {
    private String username;
    private String password;
    private String confirmPassword;
    private String email;
}
