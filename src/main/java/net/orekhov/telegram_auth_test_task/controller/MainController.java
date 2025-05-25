package net.orekhov.telegram_auth_test_task.controller;

import org.springframework.ui.Model;
import net.orekhov.telegram_auth_test_task.security.TelegramUserDetails;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * Контроллер, обрабатывающий корневой маршрут ("/") Telegram WebApp.
 *
 * <p>Если пользователь аутентифицирован (через Telegram WebApp),
 * его данные добавляются в модель и отображается страница "index".
 * Если пользователь не прошёл аутентификацию, возвращается шаблон "unauthenticated".
 */
@Controller
public class MainController {

    /**
     * Обрабатывает GET-запрос на главную страницу "/".
     *
     * @param model модель данных для передачи в представление
     * @param user объект TelegramUserDetails, автоматически подставляемый Spring Security
     * @return имя шаблона: "index" для аутентифицированных пользователей, "unauthenticated" — в противном случае
     */
    @GetMapping("/")
    public String home(Model model, @AuthenticationPrincipal TelegramUserDetails user) {
        if (user == null) return "unauthenticated";

        model.addAttribute("user", user);
        return "index";
    }
}

