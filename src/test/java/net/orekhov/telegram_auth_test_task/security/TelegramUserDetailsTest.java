package net.orekhov.telegram_auth_test_task.security;

import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Тесты для класса {@link TelegramUserDetails}, представляющего пользователя Telegram.
 */
class TelegramUserDetailsTest {

    /**
     * Проверяет корректную инициализацию всех полей, если все данные переданы.
     */
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
        assertEquals("", user.getPassword()); // пароль всегда пуст
        assertTrue(user.isEnabled());
    }

    /**
     * Проверяет поведение при отсутствии некоторых параметров — значения должны быть пустыми строками.
     */
    @Test
    void testMissingFieldsHandledGracefully() {
        Map<String, String> initData = Map.of("id", "456");

        TelegramUserDetails user = new TelegramUserDetails(initData);

        assertEquals("456", user.getId());
        assertEquals("", user.getFirstName());  // отсутствует — ожидаем пусто
        assertEquals("", user.getLastName());
        assertEquals("", user.getUsername());
    }

    /**
     * Проверяет, что TelegramUserDetails не содержит ролей (authorities).
     */
    @Test
    void testAuthoritiesEmpty() {
        TelegramUserDetails user = new TelegramUserDetails(Map.of("id", "1"));
        Collection<? extends GrantedAuthority> authorities = user.getAuthorities();

        assertNotNull(authorities);
        assertTrue(authorities.isEmpty()); // список должен быть пуст
    }

    /**
     * Проверяет, что метод toString() возвращает строку без ошибок и с содержимым.
     */
    @Test
    void testToStringDoesNotThrow() {
        TelegramUserDetails user = new TelegramUserDetails(Map.of(
                "id", "321", "username", "bot_user"
        ));

        String str = user.toString();
        assertTrue(str.contains("TelegramUserDetails")); // наличие имени класса
        assertTrue(str.contains("bot_user"));            // наличие username
    }
}
