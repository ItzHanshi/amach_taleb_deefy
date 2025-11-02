<?php
namespace IUT\Deefy\Repository;

use PDO;
use Exception;
use IUT\Deefy\Entity\Playlist;
use IUT\Deefy\Entity\AudioTrack;
use IUT\Deefy\Entity\AlbumTrack;
use IUT\Deefy\Entity\PodcastTrack;

class DeefyRepository
{
    private PDO $pdo;
    private static ?DeefyRepository $instance = null;
    private static array $config = [];

    private function __construct(array $conf) {
        $this->pdo = new PDO($conf['dsn'], $conf['user'], $conf['pass'],
            [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
    }

    public static function getInstance(){
        if (is_null(self::$instance)) {
            self::$instance = new DeefyRepository(self::$config);
        }
        return self::$instance;
    }

    public static function setConfig(string $file) {
        $conf = parse_ini_file($file);
        if ($conf === false) {
            throw new Exception("Error reading configuration file");
        }
        self::$config = [
            'dsn'=> $conf['driver'].':host='.$conf['host'].';dbname='.$conf['database'],
            'user'=> $conf['username'],
            'pass'=> $conf['password']
        ];
    }

    // Expose PDO pour AuthnProvider::getPDO()
    public function getPdo(): PDO
    {
        return $this->pdo;
    }

    /**
     * Récupérer la liste des playlists
     */
    public function getPlaylists(): array {
        try {
            $stmt = $this->pdo->query("SELECT id, nom FROM playlist ORDER BY nom");
            $playlistsData = $stmt->fetchAll(PDO::FETCH_ASSOC);
            $playlists = [];
            foreach ($playlistsData as $data) {
                $playlist = new Playlist($data['nom']);
                $playlists[] = [
                    'id' => $data['id'],
                    'playlist' => $playlist
                ];
            }
            return $playlists;
        } catch (Exception $e) {
            throw new Exception("Erreur lors de la récupération des playlists: " . $e->getMessage());
        }
    }

    /**
     * Sauvegarder une playlist vide
     */
    public function sauvegarderPlaylistVide(string $name): array {
        try {
            $stmt = $this->pdo->prepare("INSERT INTO playlist (nom) VALUES (?)");
            $stmt->execute([$name]);
            $playlist = new Playlist($name);
            $playlistId = $this->pdo->lastInsertId();
            return ['id' => $playlistId,'playlist' => $playlist];
        } catch (Exception $e) {
            throw new Exception("Erreur lors de la création de la playlist: " . $e->getMessage());
        }
    }

    /**
     * Sauvegarder une piste
     */
    public function sauvegarderPiste(AudioTrack $track): int {
        try {
            if ($track instanceof AlbumTrack) {
                $stmt = $this->pdo->prepare("
                    INSERT INTO track (titre, duree, filename, type, artiste_album) 
                    VALUES (?, ?, ?, ?, ?)
                ");
                $stmt->execute([$track->title,$track->duration,null, 'album', $track->artist ?? '']);
            } elseif ($track instanceof PodcastTrack) {
                $stmt = $this->pdo->prepare("
                    INSERT INTO track (titre, duree, filename, type, auteur_podcast) 
                    VALUES (?, ?, ?, ?, ?)
                ");
                $stmt->execute([$track->title,$track->duration,null, 'podcast', $track->author ?? '']);
            } else {

                $stmt = $this->pdo->prepare("
                    INSERT INTO track (titre, duree, filename, type) 
                    VALUES (?, ?, ?, ?)
                ");
                $stmt->execute([$track->title,$track->duration,null, 'audio']);
            }

            return (int) $this->pdo->lastInsertId();

        } catch (Exception $e) {
            throw new Exception("Erreur lors de la sauvegarde de la piste: " . $e->getMessage());
        }
    }

    /**
     * Ajouter une piste existante à une playlist existante
     */
    public function addPistePlaylist(int $trackId, int $playlistId): void {
        try {
            $stmt = $this->pdo->prepare("SELECT COUNT(*) FROM playlist WHERE id = ?");
            $stmt->execute([$playlistId]);
            if ($stmt->fetchColumn() == 0) {
                throw new Exception("Playlist avec l'ID $playlistId n'existe pas");
            }
            $stmt = $this->pdo->prepare("SELECT COUNT(*) FROM track WHERE id = ?");
            $stmt->execute([$trackId]);
            if ($stmt->fetchColumn() == 0) {
                throw new Exception("Track avec l'ID $trackId n'existe pas");
            }
            $stmt = $this->pdo->prepare("
                SELECT COALESCE(MAX(no_piste_dans_liste), 0) + 1 
                FROM playlist2track 
                WHERE id_pl = ?
            ");
            $stmt->execute([$playlistId]);
            $nextPosition = $stmt->fetchColumn();
            $stmt = $this->pdo->prepare("
                INSERT INTO playlist2track (id_pl, id_track, no_piste_dans_liste) 
                VALUES (?, ?, ?)
            ");
            $stmt->execute([$playlistId, $trackId, $nextPosition]);
        } catch (Exception $e) {
            throw new Exception("Erreur lors de l'ajout de la piste à la playlist: " . $e->getMessage());
        }
    }
}
