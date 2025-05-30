package net.orekhov.telegram_auth_test_task.util;


import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Утиль-класс для обработки данных, полученных от Telegram WebApp.
 * В частности, содержит методы для разбора строки {@code initData}, переданной WebApp
 * при инициализации мини-приложения.
 *
 * <p>Документация Telegram WebApp initData:
 * https://core.telegram.org/bots/webapps#validating-data-received-via-the-mini-app
 */
public final class TelegramDataUtils {

    /**
     * Разбирает строку {@code initData} в карту параметров.
     * Строка имеет формат: {@code key1=value1&key2=value2&...}.
     *
     * <p>Пары без символа {@code '='} игнорируются.
     * Значения декодируются с помощью {@link URLDecoder} и {@code UTF-8} кодировки.
     *
     * @param initData строка параметров, переданная WebApp
     * @return {@link Map} с ключами и значениями параметров, или пустая карта
     */
    public static Map<String, String> parseInitData(String initData) {
        if (initData == null || initData.isBlank()) {
            return Map.of();
        }

        return Arrays.stream(initData.split("&"))
                .map(param -> param.split("=", 2))
                .filter(pair -> pair.length == 2)
                .collect(Collectors.toMap(
                        pair -> pair[0],
                        pair -> safeDecode(pair[1])
                ));
    }

    /**
     * Безопасное декодирование строки из URL формата.
     */
    private static String safeDecode(String value) {
        try {
            return URLDecoder.decode(value, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            return value; // Возвращаем как есть, если не удалось декодировать
        }
    }

    /**
     * Приватный конструктор предотвращает создание экземпляров данного утиль-класса.
     */
    private TelegramDataUtils() {}
}


