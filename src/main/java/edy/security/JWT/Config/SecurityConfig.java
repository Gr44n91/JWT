package edy.security.JWT.Config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration //Indica que esta clase es un bean de configuracion
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

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
                                .anyRequest().authenticated())
                //creamos el formulario de login por defecto
                .formLogin(withDefaults())
                .build();
    }
}
