<?php

namespace Modules\AI\app\Exceptions;

use Exception;

class ValidationException extends Exception
{
    protected int $status;

    public function __construct(string $message = "", int $status = 403)
    {
        parent::__construct($message, $status);
        $this->status = $status;
    }

    public function getStatusCode(): int
    {
        return $this->status;
    }
}
