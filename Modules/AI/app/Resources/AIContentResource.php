<?php

namespace Modules\AI\app\Resources;

use Illuminate\Http\Resources\Json\JsonResource;

class AIContentResource extends JsonResource
{
    /**
     * Transform the resource into an array.
     */
    public function toArray($request): array
    {
        return parent::toArray($request);
    }
}
