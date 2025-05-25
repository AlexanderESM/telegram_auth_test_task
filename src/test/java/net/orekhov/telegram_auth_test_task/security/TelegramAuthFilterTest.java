package net.orekhov.telegram_auth_test_task.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import net.orekhov.telegram_auth_test_task.service.TelegramAuthService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.io.IOException;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

public class TelegramAuthFilterTest {

    private TelegramAuthService authService;
    private TelegramAuthFilter filter;
    private HttpServletRequest request;
    private HttpServletResponse response;
    private FilterChain chain;

    @BeforeEach
    void setup() {
        authService = mock(TelegramAuthService.class);
        filter = new TelegramAuthFilter(authService);
        request = mock(HttpServletRequest.class);
        response = mock(HttpServletResponse.class);
        chain = mock(FilterChain.class);
        SecurityContextHolder.clearContext();
    }

    @Test
    void shouldSkipFilterIfAlreadyAuthenticated() throws ServletException, IOException {
        Authentication existingAuth = mock(Authentication.class);
        SecurityContextHolder.getContext().setAuthentication(existingAuth);

        when(request.getCookies()).thenReturn(null);

        filter.doFilterInternal(request, response, chain);

        verify(chain).doFilter(request, response);
        verifyNoInteractions(authService);
    }

    @Test
    void shouldNotAuthenticateIfNoCookies() throws ServletException, IOException {
        when(request.getCookies()).thenReturn(null);

        filter.doFilterInternal(request, response, chain);

        assertNull(SecurityContextHolder.getContext().getAuthentication());
        verify(authService, never()).validateAndExtractUserData(any());
    }

    @Test
    void shouldNotAuthenticateIfInvalidInitData() throws ServletException, IOException {
        Cookie cookie = new Cookie("tg_init_data", "invalid_data");
        when(request.getCookies()).thenReturn(new Cookie[]{cookie});
        when(authService.validateAndExtractUserData("invalid_data")).thenReturn(Optional.empty());

        filter.doFilterInternal(request, response, chain);

        assertNull(SecurityContextHolder.getContext().getAuthentication());
        verify(authService).validateAndExtractUserData("invalid_data");
    }

    @Test
    void shouldAuthenticateIfValidInitData() throws ServletException, IOException {
        Cookie cookie = new Cookie("tg_init_data", "id=123&first_name=John&username=john_doe&hash=abc123");
        when(request.getCookies()).thenReturn(new Cookie[]{cookie});
        when(authService.validateAndExtractUserData("id=123&first_name=John&username=john_doe&hash=abc123"))
                .thenReturn(Optional.of(Map.of(
                        "id", "123",
                        "first_name", "John",
                        "username", "john_doe"
                )));

        filter.doFilterInternal(request, response, chain);

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        assertNotNull(auth);
        assertTrue(auth.getPrincipal() instanceof TelegramUserDetails);
        assertEquals("john_doe", ((TelegramUserDetails) auth.getPrincipal()).getUsername());
    }
}
