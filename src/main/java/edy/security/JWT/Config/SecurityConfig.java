package edy.security.JWT.Config;

import edy.security.JWT.Jwt.JwtAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration //Indica que esta clase es un bean de configuracion
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final AuthenticationProvider authProvider;
    //Filtros
    //Lo primero que hacemos es configurar o separar que endpoint seran publicos y cuales privados
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        //Vamos a retornar el http pero antes pasara por una cadena de filtros:
        return http
                //Desabilitamos el csrf
                .csrf((crsf ->
                        crsf.disable()))
                //autorizamos endpoint "auth/**" y el resto tienen seguridad
                .authorizeHttpRequests(authRequest ->
                        authRequest
                                .requestMatchers("/auth/**").permitAll()
                                .requestMatchers("/h2-console/**").permitAll()
                                .anyRequest().authenticated())
                //Desactivamos las sesiones
                .sessionManagement(sessionManager ->
                        sessionManager
                                .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                //Pasamos el Authentication Provider
                .authenticationProvider(authProvider)
                //Pasamos nuestro filtro JWT
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .build();
    }
}
