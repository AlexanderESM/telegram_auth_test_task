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

    /**
     * Telegram WebApp не использует роли, поэтому возвращается пустой список.
     */
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of();
    }

    /**
     * Telegram WebApp не использует пароль. Возвращается пустая строка во избежание NPE.
     */
    @Override
    public String getPassword() {
        return "";
    }

    /**
     * Возвращает Telegram username (может быть пустым, если Telegram не передал его).
     */
    @Override
    public String getUsername() {
        return username;
    }

    @Override public boolean isAccountNonExpired() { return true; }

    @Override public boolean isAccountNonLocked() { return true; }

    @Override public boolean isCredentialsNonExpired() { return true; }

    @Override public boolean isEnabled() { return true; }

    /**
     * Возвращает ID пользователя Telegram (в виде строки).
     */
    public String getId() {
        return id;
    }

    /**
     * Возвращает имя пользователя (first_name).
     */
    public String getFirstName() {
        return firstName;
    }

    /**
     * Возвращает фамилию пользователя (last_name).
     */
    public String getLastName() {
        return lastName;
    }
}

