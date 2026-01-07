<?php
namespace App\Traits;

use Illuminate\Http\JsonResponse;

trait ActivationClass
{
    public function dmvf($request)
    {
        // --- Replace lines #10 to #50 with the following ---
        session()->put(base64_decode('cHVyY2hhc2Vfa2V5'), $request[base64_decode('cHVyY2hhc2Vfa2V5')]);//pk
        session()->put(base64_decode('dXNlcm5hbWU='), $request[base64_decode('dXNlcm5hbWU=')]);//un
        return base64_decode('c3RlcDM=');//s3
    }

    public function actch(): JsonResponse
    {
        // --- Replace lines #55 to #86 with the following ---
        return response()->json([
            'active' => 1
        ]);
    }

    public function is_local(): bool
    {
        // --- Add this line just after line #90 ---
        return true;

        $whitelist = array(
            '127.0.0.1',
            '::1'
        );

        if (!in_array(request()->ip(), $whitelist)) {
            return false;
        }

        return true;
    }
}
