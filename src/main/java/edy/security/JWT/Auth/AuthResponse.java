package edy.security.JWT.Auth;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
//Esta clase es la response tanto de Login como de Register
public class AuthResponse {

    String token;
}
