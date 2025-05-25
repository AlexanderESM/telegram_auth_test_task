package net.orekhov.telegram_auth_test_task.security;

import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class TelegramUserDetailsTest {

    @Test
    void testFullInitData() {
        Map<String, String> initData = Map.of(
                "id", "123",
                "first_name", "Alice",
                "last_name", "Smith",
                "username", "alice_bot"
        );

        TelegramUserDetails user = new TelegramUserDetails(initData);

        assertEquals("123", user.getId());
        assertEquals("Alice", user.getFirstName());
        assertEquals("Smith", user.getLastName());
        assertEquals("alice_bot", user.getUsername());
        assertEquals("", user.getPassword());
        assertTrue(user.isEnabled());
    }

    @Test
    void testMissingFieldsHandledGracefully() {
        Map<String, String> initData = Map.of("id", "456");

        TelegramUserDetails user = new TelegramUserDetails(initData);

        assertEquals("456", user.getId());
        assertEquals("", user.getFirstName());
        assertEquals("", user.getLastName());
        assertEquals("", user.getUsername());
    }

    @Test
    void testAuthoritiesEmpty() {
        TelegramUserDetails user = new TelegramUserDetails(Map.of("id", "1"));
        Collection<? extends GrantedAuthority> authorities = user.getAuthorities();

        assertNotNull(authorities);
        assertTrue(authorities.isEmpty());
    }

    @Test
    void testToStringDoesNotThrow() {
        TelegramUserDetails user = new TelegramUserDetails(Map.of(
                "id", "321", "username", "bot_user"
        ));

        String str = user.toString();
        assertTrue(str.contains("TelegramUserDetails"));
        assertTrue(str.contains("bot_user"));
    }
}
