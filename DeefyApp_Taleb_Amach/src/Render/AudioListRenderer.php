<?php

namespace IUT\Deefy\Render;

use IUT\Deefy\Entity\AudioList;

class AudioListRenderer implements RenderInterface
{
    public function __construct(private AudioList $audioList)
    {
    }

    public function render(int $selector = RenderInterface::COMPACT): string
    {
        $tracksRender = '';
        foreach ($this->audioList->getTracks() as $track) {
            $tracksRender .= $track->title;
        }
        return sprintf(
            '%s %s %s %s',
            $this->audioList->getName(),
            $tracksRender,
            $this->audioList->getTrackCount(),
            $this->audioList->getDuration()
        );
    }

}