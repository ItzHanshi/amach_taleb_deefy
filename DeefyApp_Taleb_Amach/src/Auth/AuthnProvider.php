<?php
namespace IUT\Deefy\Auth;

use PDO;

class AuthnProvider
{
    private static ?PDO $pdo = null;

    public static function setPDO(PDO $pdo): void
    {
        self::$pdo = $pdo;
    }

    private static function getPDO(): PDO
    {
        if (self::$pdo instanceof PDO) {
            return self::$pdo;
        }

        $candidates = [
            'IUT\\Deefy\\Repository\\DeefyRepository',
            'IUT\\Deefy\\repository\\DeefyRepository'
        ];

        foreach ($candidates as $class) {
            if (class_exists($class)) {
                try {
                    $repo = $class::getInstance();
                    if (method_exists($repo, 'getPdo')) {
                        $pdo = $repo->getPdo();
                        if ($pdo instanceof PDO) {
                            return $pdo;
                        }
                    }
                } catch (\Throwable $e) {
                    // ignore and try next candidate
                }
            }
        }

        throw new AuthnException('PDO non initialisé pour AuthnProvider. Appelez AuthnProvider::setPDO($pdo) ou exposez DeefyRepository::getPdo().');
    }

    public static function signin(string $email, string $password): array
    {
        $email = trim($email);
        if ($email === '' || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
            throw new AuthnException('Email invalide.');
        }

        $pdo = self::getPDO();
        $stmt = $pdo->prepare('SELECT id, email, passwd, role FROM `User` WHERE email = :email LIMIT 1');
        $stmt->execute([':email' => $email]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$user) {
            throw new AuthnException('Utilisateur introuvable.');
        }

        $hash = $user['passwd'] ?? $user['password'] ?? null;
        if (!isset($hash) || !password_verify($password, $hash)) {
            throw new AuthnException('Mot de passe incorrect.');
        }

        unset($user['passwd'], $user['password']);
        return $user;
    }

    /**
     * Enregistre un nouvel utilisateur.
     * - vérifie email valide
     * - mot de passe min 10 caractères
     * - vérifie unicité email
     * - hache le mot de passe (BCRYPT cost=12)
     * - insère dans la table `User` avec role = 1
     *
     * Retourne le tableau utilisateur inséré (id, email, role) ou lance AuthnException.
     */
    public static function register(string $email, string $password): array
    {
        $email = trim($email);
        if ($email === '' || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
            throw new AuthnException('Email invalide.');
        }

        if (strlen($password) < 10) {
            throw new AuthnException('Le mot de passe doit contenir au moins 10 caractères.');
        }

        $pdo = self::getPDO();

        try {
            // Vérifier unicité
            $stmt = $pdo->prepare('SELECT COUNT(*) FROM `User` WHERE email = :email');
            $stmt->execute([':email' => $email]);
            if ($stmt->fetchColumn() > 0) {
                throw new AuthnException('Un compte avec cet email existe déjà.');
            }

            // Hachage du mot de passe - BCRYPT cost 12 (compatible avec password_verify)
            $hash = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
            if ($hash === false) {
                throw new AuthnException('Échec du hachage du mot de passe.');
            }

            // Insérer l'utilisateur avec role = 1
            $insert = $pdo->prepare('INSERT INTO `User` (email, passwd, role) VALUES (:email, :passwd, :role)');
            $insert->execute([
                ':email' => $email,
                ':passwd' => $hash,
                ':role' => 1
            ]);

            $id = (int) $pdo->lastInsertId();

            return ['id' => $id, 'email' => $email, 'role' => 1];
        } catch (AuthnException $e) {
            throw $e;
        } catch (\Throwable $e) {
            throw new AuthnException('Erreur lors de l\'inscription : ' . $e->getMessage());
        }
    }
    public static function getSignedInUser(): array
    {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }

        if (!isset($_SESSION['user']) || !is_array($_SESSION['user'])) {
            throw new AuthnException('Aucun utilisateur authentifié.');
        }

        return $_SESSION['user'];
    }
}
