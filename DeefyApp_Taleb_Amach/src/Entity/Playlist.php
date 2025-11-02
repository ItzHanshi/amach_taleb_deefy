<?php

namespace IUT\Deefy\Entity;

class Playlist extends AudioList
{
    public int $duration;
    public function addTrack(AudioTrack $track): void
    {
        $index = $this->getIndexIfTrackExist($track);
        if ($index !== false) {
            return;
        }

        $this->tracks[] = $track;
        $this->countTracks();
        $this->duration();
    }

    public function addTracks(AudioTrack ...$tracks): void
    {
        foreach ($tracks as $track) {
            $this->addTrack($track);
        }
    }

    public function removeTrack(AudioTrack $track): void
    {
        $index = $this->getIndexIfTrackExist($track);
        if ($index !== false) {
            unset($this->tracks[$index]);
            $this->tracks = array_values($this->tracks);
        }

        $this->countTracks();
        $this->duration();
    }

    private function getIndexIfTrackExist(AudioTrack $track): int|false
    {
        return array_search($track, $this->tracks, true);
    }
}