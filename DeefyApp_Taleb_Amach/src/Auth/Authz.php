<?php
namespace IUT\Deefy\Auth;

use IUT\Deefy\Repository\DeefyRepository;
use PDO;

class Authz
{
    public const ROLE_ADMIN = 100;

    /**
     * Vérifie que l'utilisateur authentifié a le rôle attendu.
     * Lance AuthnException si non autorisé ou pas connecté.
     */
    public static function checkRole(int $expectedRole): void
    {
        $user = AuthnProvider::getSignedInUser();
        if (!isset($user['role']) || (int)$user['role'] !== $expectedRole) {
            throw new AuthnException('Rôle insuffisant pour accéder à cette ressource.');
        }
    }

    /**
     * Vérifie que la playlist identifiée par $playlistId appartient à l'utilisateur
     * connecté ou que l'utilisateur est administrateur (ROLE_ADMIN)
     * Lance AuthnException si accès refusé ou playlist introuvable
     */
    public static function checkPlaylistOwner(int $playlistId): void
    {
        $user = AuthnProvider::getSignedInUser();

        // admin bypass
        if (isset($user['role']) && (int)$user['role'] === self::ROLE_ADMIN) {
            return;
        }

        $repo = DeefyRepository::getInstance();
        $pdo = $repo->getPdo();

        // vérifier que la playlist existe
        $stmt = $pdo->prepare('SELECT COUNT(*) FROM playlist WHERE id = ?');
        $stmt->execute([$playlistId]);
        if ($stmt->fetchColumn() == 0) {
            throw new AuthnException('Playlist introuvable.');
        }

        $userId = isset($user['id']) ? (int)$user['id'] : null;
        if ($userId === null) {
            throw new AuthnException('Utilisateur non identifié.');
        }

        // vérifier la relation dans user2playlist
        $stmt = $pdo->prepare('SELECT COUNT(*) FROM user2playlist WHERE id_pl = ? AND id_user = ?');
        $stmt->execute([$playlistId, $userId]);
        if ($stmt->fetchColumn() == 0) {
            throw new AuthnException('Accès refusé : vous n’êtes pas le propriétaire de cette playlist.');
        }
    }
}
