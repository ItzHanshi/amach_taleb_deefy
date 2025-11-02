<?php
namespace IUT\Deefy\Action;

use IUT\Deefy\Entity\Playlist;
use IUT\Deefy\Entity\AlbumTrack;
use IUT\Deefy\Entity\PodcastTrack;
use IUT\Deefy\Render\AudioListRenderer;
use IUT\Deefy\Render\RenderInterface;

class DisplayPlaylistAction extends Action
{
    public function execute(): string
    {
        
        $playlist = new Playlist("Ma Super Playlist");
        $playlist->addTrack(new AlbumTrack("Track 1", "Artiste 1"));
        $playlist->addTrack(new PodcastTrack("Podcast 1", "Auteur 1"));

        
        $renderer = new AudioListRenderer($playlist);
        $playlistHtml = $renderer->render(RenderInterface::LONG);

        return "
            <h2>Ma Playlist</h2>
            <div class='playlist'>$playlistHtml</div>
            <p><a href='index.php?action=add-track'>Ajouter une piste</a></p>
            <p><a href='index.php'>Retour à l'accueil</a></p>
        ";
    }
}
