<?php

namespace Modules\AI\Helpers;

use Illuminate\Support\Facades\Auth;

class CurrentAuthUser
{
    public static function id(): ?int
    {
        if (request()->has('seller') && request()->seller) {
            return request()->seller->id;
        }
        if (Auth::guard('seller')->check()) {
            return Auth::guard('seller')->id();
        }

        if (Auth::guard('admin')->check()) {
            return Auth::guard('admin')->id();
        }
        return null;
    }

    public static function model(): ?object
    {
        if (request()->has('seller') && request()->seller) {
            return request()->seller;
        }
        if (Auth::guard('seller')->check()) {
            return Auth::guard('seller')->user();
        }
        if (Auth::check()) {
            return Auth::guard('admin')->user();
        }
        return null;
    }
}
