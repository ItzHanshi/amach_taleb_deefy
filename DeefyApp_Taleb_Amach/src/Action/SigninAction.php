<?php
namespace IUT\Deefy\Action;

use IUT\Deefy\Auth\AuthnProvider;
use IUT\Deefy\Auth\AuthnException;

class SigninAction extends Action
{
    public function execute(): string
    {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }

        if ($_SERVER['REQUEST_METHOD'] === 'GET') {
            return $this->renderForm();
        }

        // POST
        $email = $_POST['email'] ?? '';
        $password = $_POST['password'] ?? '';

        try {
            $user = AuthnProvider::signin($email, $password);
            $_SESSION['user'] = $user;
            return "<p>Authentification réussie. Bienvenue, " . htmlspecialchars($user['email'], ENT_QUOTES, 'UTF-8') . ".</p>
                    <p><a href='index.php'>Retour</a></p>";
        } catch (AuthnException $e) {
            return "<p>Erreur d'authentification : " . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8') . "</p>
                    <p><a href='index.php?action=signin'>Réessayer</a></p>";
        }
    }

    private function renderForm(): string
    {
        return <<<HTML
        <h2>Se connecter</h2>
        <form method="POST" action="index.php?action=signin">
            <label>Email: <input type="email" name="email" required></label><br><br>
            <label>Mot de passe: <input type="password" name="password" required></label><br><br>
            <button type="submit">Se connecter</button>
        </form>
        HTML;
    }
}
