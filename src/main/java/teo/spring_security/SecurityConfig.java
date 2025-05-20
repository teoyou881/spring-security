package teo.spring_security;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@EnableWebSecurity
@Configuration
public class SecurityConfig {

  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http.authorizeHttpRequests(auth -> auth
            .requestMatchers("/logoutSuccess").permitAll()
            .anyRequest().authenticated())
        .formLogin(Customizer.withDefaults())
        .logout(logout->logout
            .logoutUrl("/logoutProc")
            .logoutRequestMatcher(new AntPathRequestMatcher("/logoutProc","POST"))
            .logoutSuccessUrl("/logoutSuccess")
            .logoutSuccessHandler((request,response,authentication)->{
              response.sendRedirect("/logoutSuccess");
            })
            .deleteCookies("JSESSIONID", "remember-me")
            .invalidateHttpSession(true)  // 👉 세션만 무효화
            .clearAuthentication(true)    // 👉 인증 객체만 null로 설정
            // securityContext 를 명시적으로 지우는 기본 기능은 없다.
            // 자동으로 지워진다. 어떻게?
            // Spring Security의 로그아웃 처리 핵심 클래스인 SecurityContextLogoutHandler를 보면,
            // 마지막에 무조건 아래 코드를 호출해:
            // SecurityContextHolder.clearContext();
            // 즉, Spring Security의 로그아웃 처리 로직에 원래 들어 있음.
            .addLogoutHandler(new LogoutHandler() {
              @Override
              public void logout(HttpServletRequest request, HttpServletResponse response,
                  Authentication authentication) {
                request.getSession().invalidate();
                SecurityContextHolder.getContextHolderStrategy().getContext().setAuthentication(null);
                SecurityContextHolder.getContextHolderStrategy().clearContext();

                // 쿠키 제거
                Cookie[] cookies = request.getCookies();
                if (cookies != null) {
                  for (Cookie cookie : cookies) {
                    if ("JSESSIONID".equals(cookie.getName()) || "remember-me".equals(cookie.getName())) {
                      cookie.setValue("");
                      cookie.setPath("/");
                      cookie.setMaxAge(0);
                      response.addCookie(cookie);
                    }
                  }
                }
              }
            })
            .permitAll()
    );
    return http.build();
  }


  @Bean
  public UserDetailsService userDetailsService(){
    UserDetails user = User.withUsername("user").password("{noop}123").roles("USER").build();
    return new InMemoryUserDetailsManager(user);
  }
}
