<?php

namespace App\Http\Controllers\Admin;

use App\Http\Controllers\Controller;
use Brian2694\Toastr\Facades\Toastr;
use File;
use Illuminate\Support\Facades\DB;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Contracts\Support\Renderable;

class DatabaseSettingsController extends Controller
{
    /**
     * @return Renderable
     */
    public function databaseIndex(): Renderable
    {
        $rawTables = DB::select('SHOW TABLES');
        $databaseName = DB::getDatabaseName();
        $key = 'Tables_in_' . $databaseName;

        $tables = collect($rawTables)->map(function ($table) use ($key) {
            return $table->$key ?? null;
        })->filter()->values()->toArray();

        $filterTables = [];
        $tables = array_values(array_diff($tables, $filterTables));

        $rows = [];
        foreach ($tables as $table) {
            $rows[] = DB::table($table)->count();
        }
        return view('admin-views.business-settings.db-index', compact('tables', 'rows'));
    }

    /**
     * @param Request $request
     * @return RedirectResponse
     */
    public function cleanDatabase(Request $request): RedirectResponse
    {
        $tables = (array)$request->tables;

        if(count($tables) == 0) {
            Toastr::error(translate('No Table Updated'));
            return back();
        }

        try {
            DB::transaction(function () use ($tables) {
                foreach ($tables as $table) {
                    DB::table($table)->delete();
                }
            });
        } catch (\Exception $exception) {
            Toastr::error(translate('Failed to update!'));
            return back();
        }

        Toastr::success(translate('Updated successfully!'));
        return back();
    }
}
