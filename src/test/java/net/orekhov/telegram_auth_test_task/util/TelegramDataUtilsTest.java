package net.orekhov.telegram_auth_test_task.util;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class TelegramDataUtilsTest {

    @Test
    void parseInitData_shouldParseValidData() {
        String initData = "id=12345&first_name=Ivan&username=test_user";
        Map<String, String> result = TelegramDataUtils.parseInitData(initData);

        assertEquals(3, result.size());
        assertEquals("12345", result.get("id"));
        assertEquals("Ivan", result.get("first_name"));
        assertEquals("test_user", result.get("username"));
    }

    @Test
    void parseInitData_shouldDecodeUrlValues() {
        String initData = "first_name=Ivan%20Petrov&city=Moscow%2FRegion";
        Map<String, String> result = TelegramDataUtils.parseInitData(initData);

        assertEquals("Ivan Petrov", result.get("first_name"));
        assertEquals("Moscow/Region", result.get("city"));
    }

    @Test
    void parseInitData_shouldIgnorePairsWithoutEqualsSign() {
        String initData = "id=12345&invalidpair&first_name=Ivan";
        Map<String, String> result = TelegramDataUtils.parseInitData(initData);

        assertEquals(2, result.size());
        assertTrue(result.containsKey("id"));
        assertTrue(result.containsKey("first_name"));
        assertFalse(result.containsKey("invalidpair"));
    }

    @Test
    void parseInitData_shouldReturnEmptyMapOnNullOrEmptyInput() {
        assertTrue(TelegramDataUtils.parseInitData(null).isEmpty());
        assertTrue(TelegramDataUtils.parseInitData("").isEmpty());
        assertTrue(TelegramDataUtils.parseInitData("     ").isEmpty());
    }

    @Test
    void parseInitData_shouldHandleMalformedEncodingGracefully() {
        String brokenValue = "name=John%XY";  // некорректная %-escape последовательность
        Map<String, String> result = TelegramDataUtils.parseInitData(brokenValue);

        assertEquals("John%XY", result.get("name")); // не декодируется — оставляем как есть
    }
}
