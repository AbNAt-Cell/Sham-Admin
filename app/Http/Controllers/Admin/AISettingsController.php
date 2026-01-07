<?php

namespace App\Http\Controllers\Admin;

use App\CentralLogics\Helpers;
use App\Http\Controllers\Controller;
use App\Model\Banner;
use App\Model\Category;
use App\Model\Product;
use Brian2694\Toastr\Facades\Toastr;
use Illuminate\Contracts\Support\Renderable;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Modules\AI\app\Models\AISetting;

class AISettingsController extends Controller
{
    public function __construct(
        private AISetting $AISetting
    )
    {
    }


    public function AIConfigurationIndex(Request $request)
    {
        $data = $this->AISetting->where('ai_name', 'OpenAI')->first();
        return view('admin-views.business-settings.ai.ai-settings', compact('data'));
    }

    public function AIConfigurationUpdate(Request $request)
    {
        $request->validate([
            'api_key' => 'required',
            'organization_id' => 'required',
        ]);

        $this->AISetting->updateOrCreate(
            ['ai_name' => 'OpenAI'],
            [
                'ai_name' => 'OpenAI',
                'api_key' => $request->api_key,
                'organization_id' => $request->organization_id,
                'status' => $request->has('status') ? 1 : 0,
            ]
        );

        Toastr::success(translate('Successfully Updated'));
        return back();
    }

}
