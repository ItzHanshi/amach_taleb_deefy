<?php

namespace IUT\Deefy\Entity;

class PodcastTrack extends AudioTrack {
    protected string $author;
    public function __construct(protected string $title, string $author)
    {
        parent::__construct($title, 10);
        $this->author = $author;
    }
}