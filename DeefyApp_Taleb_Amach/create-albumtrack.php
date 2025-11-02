<?php

require_once "vendor/autoload.php";

use IUT\Deefy\Entity\AlbumTrack;
use IUT\Deefy\CookieProvider;
use IUT\Deefy\Render\AlbumTrackRenderer;

const COOKIE_ALBUM_TRACK_NAME = 'album_track';

$track = new AlbumTrack('Song Title', 'Artist Name');
$trackSerialized = serialize($track);

$cookieProvider = new CookieProvider();
$cookieProvider->createCookie(COOKIE_ALBUM_TRACK_NAME, $trackSerialized);

$savedTrackSerialized = $cookieProvider->getCookie(COOKIE_ALBUM_TRACK_NAME);
$albumTrackUnserialize = unserialize($savedTrackSerialized);

$albumTrackRender = new AlbumTrackRenderer($albumTrackUnserialize);
echo $albumTrackRender->render(\IUT\Deefy\Render\AudioListRenderer::COMPACT);

