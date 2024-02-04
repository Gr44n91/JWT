package edy.security.JWT.Auth;

import edy.security.JWT.Jwt.JwtService;
import edy.security.JWT.User.Role;
import edy.security.JWT.User.User;
import edy.security.JWT.User.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {
    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    public AuthResponse login(LoginRequest request) {
        //Para hacer el login debemos usar una instancia del AuthenticationManager
        //y llamar al metodo login
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(request.getUsername(),
                request.getPassword()));
        //Generamos el tokem, para ello necesitaremos un objeto UserDetails
        UserDetails user = userRepository.findByUsername(request.getUsername()).orElseThrow();
        String token = jwtService.getToken(user);
        return AuthResponse.builder()
                .token(token)
                .build();
    }
    public AuthResponse register(RegisterRequest request) {
        //Importante usar la Clase User creada por nosotros no la dada por Spring
        //La vamos a setear desde el RegisterRequest con el Builder
        User user = User.builder()
                .username(request.getUsername())
                .password(passwordEncoder.encode(request.getPassword()))
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .country(request.getCountry())
                //En el caso del Role como nuestro RegisterRequest no tiene rol
                //cuando se crae el usuario por primera vez se le asigna User
                //desde nuestra Enum
                .role(Role.USER)
                .build();
        //Guardamos el usuario registrado en la BD
        userRepository.save(user);
        //Generamos el token para la respuesta
        //Para generar el Token vamos a crear un servicio nuevo JWTService
        return AuthResponse.builder()
                .token(jwtService.getToken(user))
                .build();
    }
}
