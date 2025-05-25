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
 * Отключает дефолтную форму логина и добавляет кастомный фильтр {@link TelegramAuthFilter}
 * для обработки initData от Telegram и установки аутентификации.
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final TelegramAuthFilter telegramAuthFilter;

    /**
     * Конструктор, внедряющий TelegramAuthFilter.
     *
     * @param telegramAuthFilter фильтр, обрабатывающий Telegram initData
     */
    public SecurityConfig(TelegramAuthFilter telegramAuthFilter) {
        this.telegramAuthFilter = telegramAuthFilter;
    }

    /**
     * Определяет политику безопасности для приложения:
     * <ul>
     *     <li>Разрешает доступ к публичным маршрутам (/, /unauthenticated, статика)</li>
     *     <li>Требует аутентификацию для всех остальных запросов</li>
     *     <li>Добавляет TelegramAuthFilter перед UsernamePasswordAuthenticationFilter</li>
     *     <li>Отключает logout (если не нужен)</li>
     *     <li>Оставляет httpBasic и formLogin по умолчанию (можно отключить)</li>
     * </ul>
     *
     * @param http HttpSecurity DSL
     * @return SecurityFilterChain
     * @throws Exception при ошибке конфигурации
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .securityMatcher("/**")
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/", "/index.html", "/unauthenticated", "/css/**", "/js/**").permitAll()
                        .anyRequest().authenticated()
                )
                .addFilterBefore(telegramAuthFilter, UsernamePasswordAuthenticationFilter.class)
                .logout(logout -> logout.disable())
                .formLogin(form -> form.disable())
                .httpBasic(httpBasic -> httpBasic.disable()) // отключаем и это, если не нужно
                .build();
    }

}

