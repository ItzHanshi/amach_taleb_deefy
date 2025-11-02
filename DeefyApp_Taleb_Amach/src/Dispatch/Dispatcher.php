<?php
namespace IUT\Deefy\Dispatch;

use IUT\Deefy\Action\DefaultAction;
use IUT\Deefy\Action\DisplayPlaylistAction;
use IUT\Deefy\Action\AddPlaylistAction;
use IUT\Deefy\Action\AddPodcastTrackAction;
use IUT\Deefy\Action\SigninAction;
use IUT\Deefy\Action\AddUserAction;

class Dispatcher
{
    private string $action;

    public function __construct()
    {
        $this->action = $_GET['action'] ?? 'default';
    }

    public function run(): void
    {
        $html = match($this->action) {
            'add-playlist' => (new \IUT\Deefy\Action\AddPlaylistAction())->execute(),
            'add-track' => (new \IUT\Deefy\Action\AddPodcastTrackAction())->execute(),
            'add-user' => (new \IUT\Deefy\Action\AddUserAction())->execute(),
            'signin' => (new \IUT\Deefy\Action\SigninAction())->execute(),
            default => (new \IUT\Deefy\Action\DefaultAction())->execute(),
        };
        $this->renderPage($html);
    }
private function renderPage(string $html): void
    {
        echo <<<HTML
        <!DOCTYPE html>
        <html lang="fr">
        <head>
            <meta charset="UTF-8">
            <title>Deefy</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                .track, .playlist { background: #f4f4f4; padding: 10px; border-radius: 5px; margin-bottom: 10px; }
                form { margin-bottom: 20px; }
            </style>
        </head>
        <body>
            <header>
                <h1>Deefy</h1>
            </header>
            <main>
                $html
                <p><a href='index.php'>Retour à l'accueil</a></p>
            </main>
        </body>
        </html>
        HTML;
    }
}
