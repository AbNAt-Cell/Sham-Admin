<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class ReferralCustomer extends Model
{
    use HasFactory;

    protected $fillable = [
        'user_id',
        'refer_by',
        'ref_by_earning_amount',
        'customer_discount_amount',
        'customer_discount_amount_type',
        'customer_discount_validity',
        'customer_discount_validity_type',
        'is_used',
        'is_used_by_refer',
        'is_checked',
    ];


    public function useRefferalCustomer()
    {
        return $this->belongsTo(User::class, 'user_id');
    }
    public function shareRefferalCustomer()
    {
        return $this->belongsTo(User::class, 'refer_by');
    }
}
