<?php
namespace IUT\Deefy\Action;

class DefaultAction extends Action
{
    public function execute(): string
    {
        return "
            <h1>Bienvenue sur Deefy</h1>
            <h2><a href='index.php?action=signin'>Se connecter</a></h2>
             <h2><a href='index.php?action=add-user'>S'inscrire</a></h2>
            <p>Utilisez les liens suivants pour naviguer :</p>
            <ul>
                <li><a href='index.php?action=add-track'>Ajouter une piste</a></li>
                <li><a href='index.php?action=add-playlist'>Ajouter une playlist</a></li>
                
            </ul>
        ";
    }
}
