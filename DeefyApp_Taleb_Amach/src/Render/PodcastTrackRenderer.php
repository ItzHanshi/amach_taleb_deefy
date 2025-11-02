<?php

namespace IUT\Deefy\Render;

use IUT\Deefy\Entity\PodcastTrack;

class PodcastTrackRenderer extends AudioTrackRenderer
{

    public function __construct(private PodcastTrack $track)
    {
    }

    protected function compact(): string
    {
        return $this->track->title;
    }

    protected function long(): string
    {
        return sprintf('%s by %s', $this->track->title, $this->track->author);
    }
}