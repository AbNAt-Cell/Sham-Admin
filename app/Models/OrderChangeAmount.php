<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class OrderChangeAmount extends Model
{
    use HasFactory;

    protected $fillable = [
        'order_id',
        'order_amount',
        'paid_amount',
    ];

    protected $casts = [
        'order_id' => 'integer',
        'order_amount' => 'float',
        'paid_amount' => 'float',
    ];
}
