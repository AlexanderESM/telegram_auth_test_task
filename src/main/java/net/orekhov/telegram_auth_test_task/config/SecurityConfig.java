package net.orekhov.telegram_auth_test_task.config;


import net.orekhov.telegram_auth_test_task.security.TelegramAuthFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

/**
 * Конфигурация Spring Security для Telegram WebApp.
 * <p>
 * Отключает стандартные формы логина и заголовки безопасности,
 * добавляет фильтр TelegramAuthFilter для обработки initData из WebApp.
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final TelegramAuthFilter telegramAuthFilter;

    /**
     * Конструктор с внедрением кастомного фильтра аутентификации.
     *
     * @param telegramAuthFilter фильтр, обрабатывающий Telegram initData
     */
    public SecurityConfig(TelegramAuthFilter telegramAuthFilter) {
        this.telegramAuthFilter = telegramAuthFilter;
    }

    /**
     * Настраивает цепочку фильтров безопасности:
     * - разрешает публичный доступ к начальной странице и статике;
     * - отключает стандартные формы аутентификации;
     * - отключает X-Frame-Options, чтобы Telegram WebApp мог встраивать сайт;
     * - добавляет TelegramAuthFilter перед UsernamePasswordAuthenticationFilter.
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .securityMatcher("/**")
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/", "/index.html", "/unauthenticated", "/css/**", "/js/**", "/debug.html").permitAll()
                        .anyRequest().authenticated()
                )
                .addFilterBefore(telegramAuthFilter, UsernamePasswordAuthenticationFilter.class)
                .logout(logout -> logout.disable())
                .formLogin(form -> form.disable())
                .httpBasic(httpBasic -> httpBasic.disable())

                // ✅ Отключаем только X-Frame-Options для поддержки Telegram WebApp
                .headers(headers -> headers.frameOptions(config -> config.disable()))

                .build();
    }
}

