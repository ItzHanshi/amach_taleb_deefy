<?php
namespace IUT\Deefy\Action;

use IUT\Deefy\Entity\Playlist;
use IUT\Deefy\Repository\DeefyRepository; 
use Exception;

class AddPlaylistAction extends Action
{
    public function execute(): string
    {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
        if (isset($_GET['created']) && isset($_SESSION['playlist'])) {
            return $this->renderConfirmation();
        }
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $playlistName = filter_input(INPUT_POST, 'playlist_name', FILTER_SANITIZE_SPECIAL_CHARS);
            if (empty($playlistName)) {
                return "<p>Le nom de la playlist est obligatoire.</p>
                        <p><a href='index.php?action=add-playlist'>Réessayer</a></p>";
            }
            try {
                $repo = DeefyRepository::getInstance();
                $playlistData = $repo->sauvegarderPlaylistVide($playlistName);
                
                $_SESSION['playlist'] = $playlistData['playlist'];
                $_SESSION['playlist_id'] = $playlistData['id'];
                
                
                header('Location: index.php?action=add-playlist&created=1');
                exit;
                
            } catch (Exception $e) {
                return "<p>Erreur lors de la création : " . $e->getMessage() . "</p>";
            }
        }
        else {
            return $this->renderForm();
        }
    }

    private function renderForm(): string
    {
        return <<<HTML
        <h2>Créer une playlist</h2>
        <form method="POST" action="index.php?action=add-playlist">
            <label for="playlist_name">Nom de la playlist :</label>
            <input type="text" id="playlist_name" name="playlist_name" required>
            <button type="submit">Créer</button>
        </form>
        HTML;
    }

    private function renderConfirmation(): string
    {
        $playlistName = htmlspecialchars($_SESSION['playlist']->getName(), ENT_QUOTES, 'UTF-8');
        $playlistId = $_SESSION['playlist_id'];
        return <<<HTML
        <h2>Playlist créée : $playlistName (ID: $playlistId)</h2>
        <p><a href="index.php?action=add-track">Ajouter une piste</a></p>
        HTML;
    }
}