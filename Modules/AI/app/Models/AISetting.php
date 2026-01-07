<?php

namespace Modules\AI\app\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Modules\AI\Database\factories\AISettingFactory;

/**
 * Class AISetting
 *
 * @property int $id
 * @property string $ai_name
 * @property string|null $base_url
 * @property string|null $api_key
 * @property string|null $organization_id
 * @property int|null $generate_limit
 * @property int|null $image_upload_limit
 * @property array|string|null $settings
 * @property int $status
 * @property \Carbon\Carbon|null $created_at
 * @property \Carbon\Carbon|null $updated_at
 */
class AISetting extends Model
{
    use HasFactory;

    /**
     * The table associated with the model.
     *
     * @var string
     */
    protected $table = 'ai_settings';

    /**
     * The attributes that are mass assignable.
     *
     * @var array<int, string>
     */
    protected $fillable = [
        'ai_name',
        'base_url',
        'api_key',
        'organization_id',
        'generate_limit',
        'image_upload_limit',
        'settings',
        'status',
    ];

    /**
     * Create a new factory instance for the model.
     *
     * @return \Modules\AI\Database\factories\AISettingFactory
     */
    protected static function newFactory(): AISettingFactory
    {
        // return AISettingFactory::new();
    }
}
