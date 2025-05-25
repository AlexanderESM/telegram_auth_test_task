package net.orekhov.telegram_auth_test_task.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class TelegramAuthServiceTest {

    private TelegramAuthService authService;

    @BeforeEach
    void setUp() {
        authService = new TelegramAuthService();
        authService.setBotToken("test-bot-token");
    }

    @Test
    void validateAndExtractUserData_validData_shouldReturnUserData() throws Exception {
        String initData = "id=12345&first_name=Test&username=testuser";
        String dataCheckString = "first_name=Test\nid=12345\nusername=testuser";

        // Хэш как Telegram его рассчитывает
        String expectedHash = authServiceTestHash(dataCheckString, "test-bot-token");
        String fullInitData = initData + "&hash=" + expectedHash;
        String encoded = URLEncoder.encode(fullInitData, StandardCharsets.UTF_8);

        Optional<Map<String, String>> result = authService.validateAndExtractUserData(encoded);

        assertTrue(result.isPresent());
        assertEquals("12345", result.get().get("id"));
        assertEquals("testuser", result.get().get("username"));
    }

    @Test
    void validateAndExtractUserData_missingHash_shouldReturnEmpty() {
        String badData = "id=123&first_name=Test";
        Optional<Map<String, String>> result = authService.validateAndExtractUserData(badData);
        assertTrue(result.isEmpty());
    }

    @Test
    void validateAndExtractUserData_invalidHash_shouldReturnEmpty() {
        String badData = "id=123&first_name=Test&hash=wronghash";
        Optional<Map<String, String>> result = authService.validateAndExtractUserData(badData);
        assertTrue(result.isEmpty());
    }

    @Test
    void validateAndExtractUserData_missingId_shouldReturnEmpty() {
        String badData = "username=testuser&hash=fakehash";
        Optional<Map<String, String>> result = authService.validateAndExtractUserData(badData);
        assertTrue(result.isEmpty());
    }

    @Test
    void isInitDataValid_valid_shouldReturnTrue() throws Exception {
        String base = "id=777&first_name=Bot&username=testbot";
        String dataCheck = "first_name=Bot\nid=777\nusername=testbot";
        String hash = authServiceTestHash(dataCheck, "test-bot-token");

        String full = URLEncoder.encode(base + "&hash=" + hash, StandardCharsets.UTF_8);
        assertTrue(authService.isInitDataValid(full));
    }

    @Test
    void isInitDataValid_invalid_shouldReturnFalse() {
        String bad = "id=777&first_name=Bot&hash=invalid";
        assertFalse(authService.isInitDataValid(bad));
    }

    private String authServiceTestHash(String dataCheckString, String token) throws Exception {
        TelegramAuthService testService = new TelegramAuthService();
        testService.setBotToken(token);

        // Доступ к приватному методу через reflection
        var method = TelegramAuthService.class.getDeclaredMethod("calculateHmac", String.class);
        method.setAccessible(true);
        return (String) method.invoke(testService, dataCheckString);
    }
}
