<?php

namespace IUT\Deefy\Render;

use IUT\Deefy\Entity\AlbumTrack;

class AlbumTrackRenderer extends AudioTrackRenderer
{


    public function __construct(private AlbumTrack $track)
    {
    }

    protected function compact(): string
    {
        return $this->track->title;
    }

    protected function long(): string
    {
        return sprintf('%s by %s', $this->track->title, $this->track->artist);
    }
}