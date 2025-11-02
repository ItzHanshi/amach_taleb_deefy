<?php

namespace IUT\Deefy\Entity;

class AudioList
{
    protected array $tracks = [];
    protected int $tracksCount = 0;

    public function __construct(private string $name, AudioTrack ...$tracks)
    {
        $this->tracks = $tracks;
        $this->countTracks();
        $this->duration();
    }

    public function countTracks(): void
    {
        $this->tracksCount = count($this->tracks);
    }

    public function duration(): void
    {
        $this->duration = array_reduce($this->tracks, function ($carry, $item) {
            return $carry + $item->duration;
        }, 0);
    }

    public function getTrackCount(): int
    {
        return $this->tracksCount;
    }

    public function getDuration(): int
    {
        return $this->duration;
    }

    public function getName(): string
    {
        return $this->name;
    }

    public function getTracks(): array
    {
        return $this->tracks;
    }
}