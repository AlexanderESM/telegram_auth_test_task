package net.orekhov.telegram_auth_test_task.service;

import org.apache.commons.codec.binary.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import net.orekhov.telegram_auth_test_task.util.TelegramDataUtils;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Сервис для валидации данных, полученных от Telegram WebApp через initData.
 * Использует алгоритм HMAC-SHA256 для проверки подлинности данных.
 */
@Service
public class TelegramAuthService {

    private static final Logger logger = LoggerFactory.getLogger(TelegramAuthService.class);

    @Value("${telegram.bot.token}")
    private String botToken;

    /**
     * Устанавливает токен бота вручную (например, для тестов).
     * @param token токен Telegram-бота
     */
    public void setBotToken(String token) {
        this.botToken = token;
    }

    /**
     * Валидирует initData и возвращает карту данных, если подпись верна.
     *
     * @param initData строка, полученная от Telegram WebApp
     * @return Optional с пользовательскими данными без поля hash
     */
    public Optional<Map<String, String>> validateAndExtractUserData(String initData) {
        if (initData == null || initData.isBlank()) {
            logger.warn("⚠️ Пустой или null initData получен.");
            return Optional.empty();
        }

        Map<String, String> dataMap = TelegramDataUtils.parseInitData(initData);
        String hash = dataMap.remove("hash");

        if (hash == null) {
            logger.warn("⚠️ Hash не найден в initData.");
            return Optional.empty();
        }

        String dataCheckString = dataMap.entrySet().stream()
                .sorted(Map.Entry.comparingByKey())
                .map(e -> e.getKey() + "=" + e.getValue())
                .collect(Collectors.joining("\n"));

        logger.debug("📦 dataCheckString:\n{}", dataCheckString);

        if (botToken == null || botToken.isBlank()) {
            logger.error("❌ botToken не установлен! Проверьте application.properties.");
            return Optional.empty();
        }

        try {
            Mac hmac = Mac.getInstance("HmacSHA256");
            SecretKeySpec keySpec = new SecretKeySpec(
                    ("WebAppData" + botToken).getBytes(StandardCharsets.UTF_8),
                    "HmacSHA256"
            );
            hmac.init(keySpec);
            byte[] digest = hmac.doFinal(dataCheckString.getBytes(StandardCharsets.UTF_8));
            String calcHash = Hex.encodeHexString(digest);

            logger.debug("🔐 Вычисленный хэш: {}", calcHash);
            logger.debug("🆚 Ожидаемый хэш: {}", hash);

            if (calcHash.equals(hash)) {
                logger.info("✅ Хэш совпадает. Аутентификация успешна.");
                return Optional.of(dataMap);
            } else {
                logger.warn("❌ Хэш не совпадает. Ожидалось: {}, Получено: {}", calcHash, hash);
                return Optional.empty();
            }
        } catch (Exception e) {
            logger.error("🔥 Ошибка при вычислении HMAC: {}", e.getMessage(), e);
            return Optional.empty();
        }
    }

    /**
     * Только проверка валидности initData без возврата содержимого.
     *
     * @param initData строка initData
     * @return true, если хэш валиден
     */
    public boolean isInitDataValid(String initData) {
        return validateAndExtractUserData(initData).isPresent();
    }
}

