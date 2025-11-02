<?php

require_once __DIR__ . '/vendor/autoload.php';

\IUT\Deefy\Repository\DeefyRepository::setConfig(__DIR__ . '/config/deefy.db.ini');

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}


use IUT\Deefy\Dispatch\Dispatcher;
$dispatcher = new Dispatcher();
$dispatcher->run();
