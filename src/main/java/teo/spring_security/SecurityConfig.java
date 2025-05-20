package teo.spring_security;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

@EnableWebSecurity
@Configuration
public class SecurityConfig {

  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http.authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
        .formLogin(form -> form
            // .loginPage("/loginPage")
            .loginProcessingUrl("/loginProc")
            .defaultSuccessUrl("/", true)
            .failureUrl("/failed")
            .usernameParameter("userId")
            .passwordParameter("passwd")

            //successHandler & failureHandler가 defaultSuccessUrl, failureUrl 보다 우선 작동하게 된다.
            .successHandler(new AuthenticationSuccessHandler() {
              @Override
              public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                  Authentication authentication) throws IOException, ServletException {
                System.out.println("authentication = " + authentication);
                response.sendRedirect("/home");
              }
            })
            .failureHandler(new AuthenticationFailureHandler() {
              @Override
              public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                  AuthenticationException exception) throws IOException, ServletException {
                System.out.println("exception = " + exception.getMessage());
                response.sendRedirect("/login");
              }
            })

            //failureUrl(), loginPage(), loginProcessingUrl()에 대한 URL에 모든 사용자의 접근을 허용함
            .permitAll()
        );

    return http.build();
  }
}
