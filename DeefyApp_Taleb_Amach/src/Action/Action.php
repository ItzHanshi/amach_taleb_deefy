<?php
// File: `src/Action/Action.php`
namespace IUT\Deefy\Action;

abstract class Action {

    protected ?string $http_method = null;
    protected ?string $hostname = null;
    protected ?string $script_name = null;

    public function __construct(){
        $this->http_method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
        $this->hostname = $_SERVER['HTTP_HOST'] ?? '';
        $this->script_name = $_SERVER['SCRIPT_NAME'] ?? '';
        //le Dispatcher appelle explicitement ->execute()
    }

    protected function executeGet(): string{
        return '';
    }

    protected function executePost(): string{
        return '';
    }

    public function execute(): string {
        return match ($this->http_method) {
            'GET' => $this->executeGet(),
            'POST' => $this->executePost(),
            default => ''
        };
    }
}
