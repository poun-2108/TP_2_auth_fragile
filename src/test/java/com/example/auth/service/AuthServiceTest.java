package com.example.auth.service;

import com.example.auth.dto.LoginRequest;
import com.example.auth.dto.RegisterRequest;
import com.example.auth.entity.User;
import com.example.auth.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.time.LocalDateTime;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Classe de test de AuthService.
 * Elle verifie le bon fonctionnement des methodes
 * d'inscription, de connexion et de recuperation
 * de l'utilisateur via le token.
 */
@ExtendWith(MockitoExtension.class)
public class AuthServiceTest {

    /**
     * Faux repository utilise pour simuler les acces a la base.
     */
    @Mock
    private UserRepository userRepository;

    /**
     * Service teste avec injection automatique du mock.
     */
    @InjectMocks
    private AuthService authService;

    /**
     * Outil utilise dans les tests pour generer un hash de mot de passe.
     */
    private final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    /**
     * Verifie qu'une inscription valide fonctionne correctement.
     */
    @Test
    public void testRegisterSuccess() {
        RegisterRequest request = new RegisterRequest();
        request.setName("Paul");
        request.setEmail("paul@mail.com");
        request.setPassword("Password123!");

        User savedUser = new User();
        savedUser.setName("Paul");
        savedUser.setEmail("paul@mail.com");

        when(userRepository.save(any(User.class))).thenReturn(savedUser);

        User result = authService.register(request);

        assertNotNull(result);
        assertEquals("Paul", result.getName());
        assertEquals("paul@mail.com", result.getEmail());
        verify(userRepository, times(1)).save(any(User.class));
    }

    /**
     * Verifie que le mot de passe est bien chiffre a l'inscription.
     */
    @Test
    public void testRegisterPasswordIsHashed() {
        RegisterRequest request = new RegisterRequest();
        request.setName("Paul");
        request.setEmail("paul@mail.com");
        request.setPassword("Password123!");

        ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);

        when(userRepository.save(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0));

        User result = authService.register(request);

        verify(userRepository).save(userCaptor.capture());

        User userSaved = userCaptor.getValue();

        assertNotNull(result);
        assertNotNull(userSaved.getPasswordHash());
        assertNotEquals("Password123!", userSaved.getPasswordHash());
        assertTrue(passwordEncoder.matches("Password123!", userSaved.getPasswordHash()));
    }

    /**
     * Verifie que les valeurs par defaut sont bien initialisees a l'inscription.
     */
    @Test
    public void testRegisterInitialValues() {
        RegisterRequest request = new RegisterRequest();
        request.setName("Paul");
        request.setEmail("paul@mail.com");
        request.setPassword("Password123!");

        when(userRepository.save(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0));

        User result = authService.register(request);

        assertNotNull(result.getCreatedAt());
        assertNull(result.getToken());
        assertEquals(0, result.getFailedAttempts());
        assertNull(result.getLockUntil());
    }

    /**
     * Verifie que l'inscription echoue si le nom est null.
     */
    @Test
    public void testRegisterNameNull() {
        RegisterRequest request = new RegisterRequest();
        request.setName(null);
        request.setEmail("paul@mail.com");
        request.setPassword("Password123!");

        RuntimeException exception = assertThrows(RuntimeException.class, () -> authService.register(request));
        assertEquals("Name obligatoire", exception.getMessage());
        verify(userRepository, never()).save(any(User.class));
    }

    /**
     * Verifie que l'inscription echoue si le nom est vide.
     */
    @Test
    public void testRegisterNameBlank() {
        RegisterRequest request = new RegisterRequest();
        request.setName("   ");
        request.setEmail("paul@mail.com");
        request.setPassword("Password123!");

        RuntimeException exception = assertThrows(RuntimeException.class, () -> authService.register(request));
        assertEquals("Name obligatoire", exception.getMessage());
        verify(userRepository, never()).save(any(User.class));
    }

    /**
     * Verifie que l'inscription echoue si l'email est null.
     */
    @Test
    public void testRegisterEmailNull() {
        RegisterRequest request = new RegisterRequest();
        request.setName("Paul");
        request.setEmail(null);
        request.setPassword("Password123!");

        RuntimeException exception = assertThrows(RuntimeException.class, () -> authService.register(request));
        assertEquals("Email obligatoire", exception.getMessage());
        verify(userRepository, never()).save(any(User.class));
    }

    /**
     * Verifie que l'inscription echoue si l'email est vide.
     */
    @Test
    public void testRegisterEmailBlank() {
        RegisterRequest request = new RegisterRequest();
        request.setName("Paul");
        request.setEmail("   ");
        request.setPassword("Password123!");

        RuntimeException exception = assertThrows(RuntimeException.class, () -> authService.register(request));
        assertEquals("Email obligatoire", exception.getMessage());
        verify(userRepository, never()).save(any(User.class));
    }

    /**
     * Verifie que l'inscription echoue si le mot de passe est null.
     */
    @Test
    public void testRegisterPasswordNull() {
        RegisterRequest request = new RegisterRequest();
        request.setName("Paul");
        request.setEmail("paul@mail.com");
        request.setPassword(null);

        RuntimeException exception = assertThrows(RuntimeException.class, () -> authService.register(request));
        assertEquals("Password obligatoire", exception.getMessage());
        verify(userRepository, never()).save(any(User.class));
    }

    /**
     * Verifie que l'inscription echoue si le mot de passe est vide.
     */
    @Test
    public void testRegisterPasswordBlank() {
        RegisterRequest request = new RegisterRequest();
        request.setName("Paul");
        request.setEmail("paul@mail.com");
        request.setPassword("   ");

        RuntimeException exception = assertThrows(RuntimeException.class, () -> authService.register(request));
        assertEquals("Password obligatoire", exception.getMessage());
        verify(userRepository, never()).save(any(User.class));
    }

    /**
     * Verifie que l'inscription echoue si le mot de passe
     * ne respecte pas la politique de securite.
     */
    @Test
    public void testRegisterPasswordInvalid() {
        RegisterRequest request = new RegisterRequest();
        request.setName("Paul");
        request.setEmail("paul@mail.com");
        request.setPassword("abc");

        RuntimeException exception = assertThrows(RuntimeException.class, () -> authService.register(request));
        assertEquals(
                "Password invalide : minimum 12 caracteres, 1 majuscule, 1 minuscule, 1 chiffre et 1 caractere special",
                exception.getMessage()
        );
        verify(userRepository, never()).save(any(User.class));
    }

    /**
     * Verifie qu'une connexion valide retourne bien un token.
     */
    @Test
    public void testLoginSuccess() {
        LoginRequest request = new LoginRequest();
        request.setEmail("paul@mail.com");
        request.setPassword("Password123!");

        User user = new User();
        user.setEmail("paul@mail.com");
        user.setPasswordHash(passwordEncoder.encode("Password123!"));
        user.setFailedAttempts(0);
        user.setLockUntil(null);

        when(userRepository.findByEmail("paul@mail.com")).thenReturn(Optional.of(user));
        when(userRepository.save(any(User.class))).thenReturn(user);

        String token = authService.login(request);

        assertNotNull(token);
        assertFalse(token.isBlank());
        assertEquals(0, user.getFailedAttempts());
        assertNull(user.getLockUntil());
        assertNotNull(user.getToken());
        verify(userRepository, times(1)).save(user);
    }

    /**
     * Verifie qu'une connexion reussie remet a zero
     * les tentatives echouees et le blocage.
     */
    @Test
    public void testLoginSuccessResetsFailedAttemptsAndLock() {
        LoginRequest request = new LoginRequest();
        request.setEmail("paul@mail.com");
        request.setPassword("Password123!");

        User user = new User();
        user.setEmail("paul@mail.com");
        user.setPasswordHash(passwordEncoder.encode("Password123!"));
        user.setFailedAttempts(3);
        user.setLockUntil(null);

        when(userRepository.findByEmail("paul@mail.com")).thenReturn(Optional.of(user));
        when(userRepository.save(any(User.class))).thenReturn(user);

        String token = authService.login(request);

        assertNotNull(token);
        assertEquals(0, user.getFailedAttempts());
        assertNull(user.getLockUntil());
    }

    /**
     * Verifie que la connexion echoue si l'email est null.
     */
    @Test
    public void testLoginEmailNull() {
        LoginRequest request = new LoginRequest();
        request.setEmail(null);
        request.setPassword("Password123!");

        RuntimeException exception = assertThrows(RuntimeException.class, () -> authService.login(request));
        assertEquals("Email obligatoire", exception.getMessage());
        verify(userRepository, never()).findByEmail(any());
    }

    /**
     * Verifie que la connexion echoue si l'email est vide.
     */
    @Test
    public void testLoginEmailBlank() {
        LoginRequest request = new LoginRequest();
        request.setEmail("   ");
        request.setPassword("Password123!");

        RuntimeException exception = assertThrows(RuntimeException.class, () -> authService.login(request));
        assertEquals("Email obligatoire", exception.getMessage());
        verify(userRepository, never()).findByEmail(any());
    }

    /**
     * Verifie que la connexion echoue si le mot de passe est null.
     */
    @Test
    public void testLoginPasswordNull() {
        LoginRequest request = new LoginRequest();
        request.setEmail("paul@mail.com");
        request.setPassword(null);

        RuntimeException exception = assertThrows(RuntimeException.class, () -> authService.login(request));
        assertEquals("Mot de passe obligatoire", exception.getMessage());
        verify(userRepository, never()).findByEmail(any());
    }

    /**
     * Verifie que la connexion echoue si le mot de passe est vide.
     */
    @Test
    public void testLoginPasswordBlank() {
        LoginRequest request = new LoginRequest();
        request.setEmail("paul@mail.com");
        request.setPassword("   ");

        RuntimeException exception = assertThrows(RuntimeException.class, () -> authService.login(request));
        assertEquals("Mot de passe obligatoire", exception.getMessage());
        verify(userRepository, never()).findByEmail(any());
    }

    /**
     * Verifie que la connexion echoue si l'utilisateur n'existe pas.
     */
    @Test
    public void testLoginUserNotFound() {
        LoginRequest request = new LoginRequest();
        request.setEmail("paul@mail.com");
        request.setPassword("Password123!");

        when(userRepository.findByEmail("paul@mail.com")).thenReturn(Optional.empty());

        RuntimeException exception = assertThrows(RuntimeException.class, () -> authService.login(request));
        assertEquals("Utilisateur introuvable", exception.getMessage());
    }

    /**
     * Verifie que la connexion echoue si le mot de passe est faux
     * et que le nombre d'essais est incremente.
     */
    @Test
    public void testLoginWrongPassword() {
        LoginRequest request = new LoginRequest();
        request.setEmail("paul@mail.com");
        request.setPassword("WrongPassword123!");

        User user = new User();
        user.setEmail("paul@mail.com");
        user.setPasswordHash(passwordEncoder.encode("Password123!"));
        user.setFailedAttempts(0);
        user.setLockUntil(null);

        when(userRepository.findByEmail("paul@mail.com")).thenReturn(Optional.of(user));
        when(userRepository.save(any(User.class))).thenReturn(user);

        RuntimeException exception = assertThrows(RuntimeException.class, () -> authService.login(request));
        assertEquals("Identifiants invalides", exception.getMessage());
        assertEquals(1, user.getFailedAttempts());
        verify(userRepository, times(1)).save(user);
    }

    /**
     * Verifie qu'au cinquieme mauvais essai,
     * le compte est bloque temporairement.
     */
    @Test
    public void testLoginWrongPasswordLocksAccountAfterFiveAttempts() {
        LoginRequest request = new LoginRequest();
        request.setEmail("paul@mail.com");
        request.setPassword("WrongPassword123!");

        User user = new User();
        user.setEmail("paul@mail.com");
        user.setPasswordHash(passwordEncoder.encode("Password123!"));
        user.setFailedAttempts(4);
        user.setLockUntil(null);

        when(userRepository.findByEmail("paul@mail.com")).thenReturn(Optional.of(user));
        when(userRepository.save(any(User.class))).thenReturn(user);

        RuntimeException exception = assertThrows(RuntimeException.class, () -> authService.login(request));

        assertEquals("Identifiants invalides", exception.getMessage());
        assertEquals(5, user.getFailedAttempts());
        assertNotNull(user.getLockUntil());
        verify(userRepository, times(1)).save(user);
    }

    /**
     * Verifie que la connexion echoue si le compte est temporairement bloque.
     */
    @Test
    public void testLoginBlockedAccount() {
        LoginRequest request = new LoginRequest();
        request.setEmail("paul@mail.com");
        request.setPassword("Password123!");

        User user = new User();
        user.setEmail("paul@mail.com");
        user.setPasswordHash(passwordEncoder.encode("Password123!"));
        user.setFailedAttempts(5);
        user.setLockUntil(LocalDateTime.now().plusMinutes(1));

        when(userRepository.findByEmail("paul@mail.com")).thenReturn(Optional.of(user));

        RuntimeException exception = assertThrows(RuntimeException.class, () -> authService.login(request));
        assertEquals("Compte bloque temporairement. Reessayez plus tard", exception.getMessage());
        verify(userRepository, never()).save(any(User.class));
    }

    /**
     * Verifie que la recuperation de l'utilisateur fonctionne avec un token valide.
     */
    @Test
    public void testGetMeSuccess() {
        User user = new User();
        user.setName("Paul");
        user.setEmail("paul@mail.com");
        user.setToken("abc123");

        when(userRepository.findByToken("abc123")).thenReturn(Optional.of(user));

        User result = authService.getMe("abc123");

        assertNotNull(result);
        assertEquals("Paul", result.getName());
        assertEquals("paul@mail.com", result.getEmail());
    }

    /**
     * Verifie que la recuperation echoue si le token est null.
     */
    @Test
    public void testGetMeTokenNull() {
        RuntimeException exception = assertThrows(RuntimeException.class, () -> authService.getMe(null));
        assertEquals("Token manquant", exception.getMessage());
        verify(userRepository, never()).findByToken(any());
    }

    /**
     * Verifie que la recuperation echoue si le token est vide.
     */
    @Test
    public void testGetMeTokenBlank() {
        RuntimeException exception = assertThrows(RuntimeException.class, () -> authService.getMe("   "));
        assertEquals("Token manquant", exception.getMessage());
        verify(userRepository, never()).findByToken(any());
    }

    /**
     * Verifie que la recuperation de l'utilisateur echoue
     * si le token est invalide.
     */
    @Test
    public void testGetMeTokenInvalid() {
        when(userRepository.findByToken("bad-token")).thenReturn(Optional.empty());

        RuntimeException exception = assertThrows(RuntimeException.class, () -> authService.getMe("bad-token"));
        assertEquals("Token invalide", exception.getMessage());
    }
}