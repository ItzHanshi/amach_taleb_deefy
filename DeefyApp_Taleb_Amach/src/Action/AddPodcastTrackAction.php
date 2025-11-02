<?php
namespace IUT\Deefy\Action;

use IUT\Deefy\Entity\PodcastTrack;
use IUT\Deefy\Render\AudioListRenderer;
use IUT\Deefy\Render\RenderInterface;
use IUT\Deefy\Repository\DeefyRepository; 
use Exception;

class AddPodcastTrackAction extends Action
{
    public function execute(): string
    {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
        if (isset($_GET['added']) && isset($_SESSION['playlist'])) {
            return $this->renderConfirmation();
        }
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $trackTitle = filter_input(INPUT_POST, 'track_title', FILTER_SANITIZE_SPECIAL_CHARS);
            $trackAuthor = filter_input(INPUT_POST, 'track_author', FILTER_SANITIZE_SPECIAL_CHARS);
            if (empty($trackTitle) || empty($trackAuthor)) {
                return "<p>Données manquantes.</p>
                        <p><a href='index.php?action=add-track'>Réessayer</a></p>";
            }
            if (!isset($_SESSION['playlist']) || !isset($_SESSION['playlist_id'])) {
                return "<p>Aucune playlist disponible. <a href='index.php?action=add-playlist'>Créez une playlist d'abord</a>.</p>";
            }
            try {
                $track = new PodcastTrack($trackTitle, $trackAuthor);
                $repo = DeefyRepository::getInstance();
                $trackId = $repo->sauvegarderPiste($track);
                $repo->addPistePlaylist($trackId, $_SESSION['playlist_id']);
                $_SESSION['playlist']->addTrack($track);
                header('Location: index.php?action=add-track&added=1');
                exit;
            } catch (Exception $e) {
                return "<p>Erreur lors de l'ajout : " . $e->getMessage() . "</p>";
            }
        }
        else {
            return $this->renderForm();
        }
    }

    private function renderForm(): string
    {
        return <<<HTML
        <h2>Ajouter une piste à la playlist</h2>
        <form method="POST" action="index.php?action=add-track">
            <label for="track_title">Titre de la piste :</label>
            <input type="text" id="track_title" name="track_title" required><br><br>

            <label for="track_author">Auteur :</label>
            <input type="text" id="track_author" name="track_author" required><br><br>

            <button type="submit">Ajouter la piste</button>
        </form>
        HTML;
    }

    
    private function renderConfirmation(): string
    {
        $renderer = new AudioListRenderer($_SESSION['playlist']);
        $playlistHtml = $renderer->render(RenderInterface::LONG);
        return "
            <h2>Piste ajoutée avec succès !</h2>
            <div class='playlist'>$playlistHtml</div>
            <p><a href='index.php?action=add-track'>Ajouter une autre piste</a></p>
        ";
    }
}