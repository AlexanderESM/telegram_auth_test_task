package net.orekhov.telegram_auth_test_task.security;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;
import java.util.Map;

/**
 * Реализация {@link UserDetails} для представления пользователя Telegram в Spring Security.
 *
 * <p>Telegram WebApp не использует пароль, имя пользователя или роли в классическом смысле,
 * поэтому поля {@code password} и {@code authorities} возвращаются пустыми или по умолчанию.
 */
public class TelegramUserDetails implements UserDetails {

    private final String id;
    private final String firstName;
    private final String lastName;
    private final String username;

    /**
     * Конструктор, инициализирующий поля из карты данных, полученных от Telegram (initData).
     *
     * @param data карта параметров, например: id, first_name, last_name, username
     */
    public TelegramUserDetails(Map<String, String> data) {
        this.id = data.getOrDefault("id", "");
        this.firstName = data.getOrDefault("first_name", "");
        this.lastName = data.getOrDefault("last_name", "");
        this.username = data.getOrDefault("username", "");
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(); // роли не используются
    }

    @Override
    public String getPassword() {
        return ""; // не используется
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override public boolean isAccountNonExpired() { return true; }

    @Override public boolean isAccountNonLocked() { return true; }

    @Override public boolean isCredentialsNonExpired() { return true; }

    @Override public boolean isEnabled() { return true; }

    public String getId() {
        return id;
    }

    public String getFirstName() {
        return firstName;
    }

    public String getLastName() {
        return lastName;
    }

    /**
     * Возвращает строковое представление пользователя.
     */
    @Override
    public String toString() {
        return "TelegramUserDetails{" +
                "id='" + id + '\'' +
                ", username='" + username + '\'' +
                ", firstName='" + firstName + '\'' +
                ", lastName='" + lastName + '\'' +
                '}';
    }
}

