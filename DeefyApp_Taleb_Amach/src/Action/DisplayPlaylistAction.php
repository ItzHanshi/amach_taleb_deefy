<?php
// File: `src/Action/DisplayPlaylistAction.php`
namespace IUT\Deefy\Action;

use IUT\Deefy\Repository\DeefyRepository;
use IUT\Deefy\Render\AudioListRenderer;
use IUT\Deefy\Render\RenderInterface;
use IUT\Deefy\Auth\Authz;
use IUT\Deefy\Auth\AuthnException;

class DisplayPlaylistAction extends Action
{
    public function execute(): string
    {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }

        $id = isset($_GET['id']) ? (int) $_GET['id'] : 0;
        if ($id <= 0) {
            return "<p>ID de playlist invalide.</p>";
        }

        try {
            // contrôle d'accès : propriétaire (user2playlist) ou admin
            Authz::checkPlaylistOwner($id);

            $repo = DeefyRepository::getInstance();
            $playlist = $repo->findPlaylistById($id);
            if ($playlist === null) {
                return "<p>Playlist introuvable (ID: $id).</p>";
            }

            $renderer = new AudioListRenderer($playlist);
            $playlistHtml = $renderer->render(RenderInterface::LONG);

            return "
                <h2>Playlist: " . htmlspecialchars($playlist->getName(), ENT_QUOTES, 'UTF-8') . "</h2>
                <div class='playlist'>$playlistHtml</div>
            ";
        } catch (AuthnException $e) {
            return "<p>Accès refusé : " . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8') . "</p>";
        } catch (\Exception $e) {
            return "<p>Erreur lors de l'affichage de la playlist : " . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8') . "</p>";
        }
    }
}
