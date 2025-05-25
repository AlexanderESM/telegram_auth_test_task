package net.orekhov.telegram_auth_test_task.controller;

import net.orekhov.telegram_auth_test_task.security.TelegramUserDetails;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.List;
import java.util.Map;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Юнит-тесты для контроллера {@link MainController}.
 * Проверяет поведение при аутентифицированном и неаутентифицированном пользователе.
 */
@WebMvcTest(MainController.class)
class MainControllerTest {

    @Autowired
    private MockMvc mockMvc;

    /**
     * Тестирует поведение при отсутствии аутентифицированного пользователя.
     * Ожидается, что контроллер вернёт представление "unauthenticated".
     */
    @Test
    void whenUserIsNotAuthenticated_thenReturnUnauthenticatedView() throws Exception {
        mockMvc.perform(get("/"))
                .andExpect(status().isOk()) // Ожидаем HTTP 200
                .andExpect(view().name("unauthenticated")); // Ожидаем шаблон "unauthenticated"
    }

    /**
     * Тестирует поведение при наличии аутентифицированного пользователя.
     * Ожидается, что контроллер вернёт шаблон "index" и добавит объект пользователя в модель.
     */
    @Test
    void whenUserIsAuthenticated_thenReturnIndexViewWithUser() throws Exception {
        // Подготавливаем пользователя
        TelegramUserDetails user = new TelegramUserDetails(Map.of(
                "id", "123",
                "first_name", "Ivan",
                "last_name", "Petrov",
                "username", "ivan_petrov"
        ));

        // Создаём объект аутентификации
        Authentication auth = new UsernamePasswordAuthenticationToken(user, null, List.of());

        // Выполняем GET-запрос с этим пользователем
        mockMvc.perform(get("/").with(authentication(auth)))
                .andExpect(status().isOk()) // Ожидаем HTTP 200
                .andExpect(view().name("index")) // Ожидаем шаблон "index"
                .andExpect(model().attribute("user", user)); // Проверяем наличие пользователя в модели
    }
}
