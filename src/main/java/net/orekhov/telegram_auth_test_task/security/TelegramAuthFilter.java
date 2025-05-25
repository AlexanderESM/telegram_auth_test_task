package net.orekhov.telegram_auth_test_task.security;


import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import net.orekhov.telegram_auth_test_task.service.TelegramAuthService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Map;
import java.util.Optional;

/**
 * Фильтр аутентификации Telegram WebApp.
 * <p>
 * Извлекает initData из cookies, валидирует через {@link TelegramAuthService},
 * и устанавливает {@link Authentication} в SecurityContext при успехе.
 */
@Component
public class TelegramAuthFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(TelegramAuthFilter.class);
    private final TelegramAuthService authService;

    /**
     * Внедрение сервиса валидации initData.
     *
     * @param authService сервис Telegram-аутентификации
     */
    public TelegramAuthFilter(TelegramAuthService authService) {
        this.authService = authService;
    }

    /**
     * Основная логика фильтра: проверка наличия и валидности initData из cookie.
     * При успешной валидации создаёт аутентификационный объект.
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        Cookie[] cookies = request.getCookies();

        //  Лог всех cookie
        if (cookies != null) {
            Arrays.stream(cookies).forEach(c ->
                    logger.debug(" Cookie: {} = {}", c.getName(), c.getValue()));
        } else {
            logger.warn(" Cookie-массив отсутствует (null)");
        }

        // Извлекаем initData
        String initDataRaw = extractInitDataFromCookies(cookies);
        String initData = initDataRaw != null ? URLDecoder.decode(initDataRaw, StandardCharsets.UTF_8) : null;

        logger.info("initData from cookie (decoded): {}", initData);

        if (initData == null || initData.isBlank() || "[пусто]".equals(initData)) {
            logger.warn("Cookie 'tg_init_data' отсутствует, пуст или содержит [пусто].");
        }

        // 🛑 Проверка на уже аутентифицированного пользователя
        if (SecurityContextHolder.getContext().getAuthentication() != null) {
            logger.debug("Пользователь уже аутентифицирован — фильтр пропущен.");
            chain.doFilter(request, response);
            return;
        }

        // Валидация и установка аутентификации
        Optional<Map<String, String>> userDataOpt = authService.validateAndExtractUserData(initData);
        if (userDataOpt.isPresent()) {
            TelegramUserDetails userDetails = new TelegramUserDetails(userDataOpt.get());
            Authentication auth = new UsernamePasswordAuthenticationToken(
                    userDetails, null, userDetails.getAuthorities());
            SecurityContextHolder.getContext().setAuthentication(auth);
            logger.info("✅ Telegram-пользователь аутентифицирован: id={}, username={}",
                    userDetails.getId(), userDetails.getUsername());
        } else {
            logger.warn("Не удалось аутентифицировать пользователя — initData невалиден или отсутствует.");
        }

        chain.doFilter(request, response);
    }

    /**
     * Ищет cookie с именем "tg_init_data" и возвращает её значение.
     *
     * @param cookies массив cookie (может быть null)
     * @return строка initData или null
     */
    private String extractInitDataFromCookies(Cookie[] cookies) {
        if (cookies == null) return null;

        return Arrays.stream(cookies)
                .filter(cookie -> "tg_init_data".equals(cookie.getName()))
                .map(Cookie::getValue)
                .findFirst()
                .orElse(null);
    }
}
