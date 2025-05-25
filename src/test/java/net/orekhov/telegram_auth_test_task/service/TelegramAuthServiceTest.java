package net.orekhov.telegram_auth_test_task.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Юнит-тесты для {@link TelegramAuthService}.
 */
class TelegramAuthServiceTest {

    private TelegramAuthService authService;

    @BeforeEach
    void setUp() {
        authService = new TelegramAuthService();
        authService.setBotToken("test-bot-token");
    }

    /**
     * Тест: при корректных данных initData метод должен вернуть userData.
     */
    @Test
    void validateAndExtractUserData_validData_shouldReturnUserData() throws Exception {
        String initData = "id=12345&first_name=Test&username=testuser";
        String dataCheckString = "first_name=Test\nid=12345\nusername=testuser";

        // Хэш, как если бы его сгенерировал Telegram
        String expectedHash = authServiceTestHash(dataCheckString, "test-bot-token");
        String fullInitData = initData + "&hash=" + expectedHash;
        String encoded = URLEncoder.encode(fullInitData, StandardCharsets.UTF_8);

        Optional<Map<String, String>> result = authService.validateAndExtractUserData(encoded);

        assertTrue(result.isPresent());
        assertEquals("12345", result.get().get("id"));
        assertEquals("testuser", result.get().get("username"));
    }

    /**
     * Тест: если отсутствует hash — метод должен вернуть empty.
     */
    @Test
    void validateAndExtractUserData_missingHash_shouldReturnEmpty() {
        String badData = "id=123&first_name=Test";
        Optional<Map<String, String>> result = authService.validateAndExtractUserData(badData);
        assertTrue(result.isEmpty());
    }

    /**
     * Тест: если hash неверный — результат должен быть пустым.
     */
    @Test
    void validateAndExtractUserData_invalidHash_shouldReturnEmpty() {
        String badData = "id=123&first_name=Test&hash=wronghash";
        Optional<Map<String, String>> result = authService.validateAndExtractUserData(badData);
        assertTrue(result.isEmpty());
    }

    /**
     * Тест: если отсутствует поле `id` — результат должен быть пустым.
     */
    @Test
    void validateAndExtractUserData_missingId_shouldReturnEmpty() {
        String badData = "username=testuser&hash=fakehash";
        Optional<Map<String, String>> result = authService.validateAndExtractUserData(badData);
        assertTrue(result.isEmpty());
    }

    /**
     * Тест: isInitDataValid должен вернуть true при корректных данных.
     */
    @Test
    void isInitDataValid_valid_shouldReturnTrue() throws Exception {
        String base = "id=777&first_name=Bot&username=testbot";
        String dataCheck = "first_name=Bot\nid=777\nusername=testbot";
        String hash = authServiceTestHash(dataCheck, "test-bot-token");

        String full = URLEncoder.encode(base + "&hash=" + hash, StandardCharsets.UTF_8);
        assertTrue(authService.isInitDataValid(full));
    }

    /**
     * Тест: isInitDataValid должен вернуть false при неверном hash.
     */
    @Test
    void isInitDataValid_invalid_shouldReturnFalse() {
        String bad = "id=777&first_name=Bot&hash=invalid";
        assertFalse(authService.isInitDataValid(bad));
    }

    /**
     * Хелпер: вызывает приватный метод calculateHmac через reflection.
     */
    private String authServiceTestHash(String dataCheckString, String token) throws Exception {
        TelegramAuthService testService = new TelegramAuthService();
        testService.setBotToken(token);

        var method = TelegramAuthService.class.getDeclaredMethod("calculateHmac", String.class);
        method.setAccessible(true);
        return (String) method.invoke(testService, dataCheckString);
    }
}
