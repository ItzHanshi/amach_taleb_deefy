<?php
namespace IUT\Deefy\Action;

use IUT\Deefy\Auth\AuthnProvider;
use IUT\Deefy\Auth\AuthnException;

class AddUserAction extends Action
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
        $email = trim($_POST['email'] ?? '');
        $password = $_POST['password'] ?? '';
        $password2 = $_POST['password_confirm'] ?? '';

        if ($password !== $password2) {
            return "<p>Les mots de passe ne correspondent pas.</p><p><a href='index.php?action=add-user'>Réessayer</a></p>";
        }

        try {
            $user = AuthnProvider::register($email, $password);
            return "<p>Inscription réussie. Bienvenue, " . htmlspecialchars($user['email'], ENT_QUOTES, 'UTF-8') . ".</p>
                    <p><a href='index.php'>Retour à l'accueil</a></p>";
        } catch (AuthnException $e) {
            return "<p>Erreur d'inscription : " . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8') . "</p>
                    <p><a href='index.php?action=add-user'>Réessayer</a></p>";
        }
    }

    private function renderForm(): string
    {
        return <<<HTML
        <h2>Inscription</h2>
        <form method="POST" action="index.php?action=add-user">
            <label>Email: <input type="email" name="email" required></label><br><br>
            <label>Mot de passe: <input type="password" name="password" required></label><br><br>
            <label>Confirmer le mot de passe: <input type="password" name="password_confirm" required></label><br><br>
            <button type="submit">S'inscrire</button>
        </form>
        HTML;
    }
}
