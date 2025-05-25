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

@WebMvcTest(MainController.class)
class MainControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void whenUserIsNotAuthenticated_thenReturnUnauthenticatedView() throws Exception {
        mockMvc.perform(get("/"))
                .andExpect(status().isOk())
                .andExpect(view().name("unauthenticated"));
    }

    @Test
    void whenUserIsAuthenticated_thenReturnIndexViewWithUser() throws Exception {
        TelegramUserDetails user = new TelegramUserDetails(Map.of(
                "id", "123",
                "first_name", "Ivan",
                "last_name", "Petrov",
                "username", "ivan_petrov"
        ));

        Authentication auth = new UsernamePasswordAuthenticationToken(user, null, List.of());

        mockMvc.perform(get("/").with(authentication(auth)))
                .andExpect(status().isOk())
                .andExpect(view().name("index"))
                .andExpect(model().attribute("user", user));
    }
}
