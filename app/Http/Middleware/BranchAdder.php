<?php

namespace App\Http\Middleware;

use App\Model\Branch;
use Closure;
use Illuminate\Support\Facades\Config;

class BranchAdder
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @return mixed
     */
    public function handle($request, Closure $next)
    {
        Config::set('branch_id', $request->header('branch-id') );

        $branch = Branch::where('id', Config::get('branch_id'))->first();
        if (!isset($branch)) {
            $errors = [];
            $errors[] = ['code' => 'branch-403', 'message' => 'Branch not match.'];
            return response()->json(['errors' => $errors], 403);
        }

        return $next($request);
    }
}
