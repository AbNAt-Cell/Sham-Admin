<?php

namespace App\Http\Controllers;

use App\Model\BusinessSetting;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Contracts\Support\Renderable;
use Illuminate\Contracts\View\Factory;
use Illuminate\Contracts\View\View;
use Illuminate\Http\Request;

class HomeController extends Controller
{
    /**
     * Create a new controller instance.
     *
     * @return void
     */
    public function __construct()
    {
        /*$this->middleware('auth');*/
    }

    /**
     * Show the application dashboard.
     *
     * @return Renderable
     */
    public function index(): Renderable
    {
        return view('home');
    }

    /**
     * @return Factory|View|Application
     */
    public function about_us(): Factory|View|Application
    {
        return view('pages.about-us');
    }

    /**
     * @return Factory|View|Application
     */
    public function terms_and_conditions(): Factory|View|Application
    {
        return view('pages.terms-and-conditions');
    }

    /**
     * @return Factory|View|Application
     */
    public function privacy_policy(): Factory|View|Application
    {
        return view('pages.privacy-policy');
    }

    public function return(){
        $data = BusinessSetting::where(['key' => 'return_page'])->first();
        $status = json_decode($data['value'],true)['status'];

        if ($status == '1') {
            return view('pages.return', compact('data'));
        }
        return redirect()->route('about-us');
    }
    public function refund()
    {
        $data = BusinessSetting::where(['key' => 'refund_page'])->first();
        $status = json_decode($data['value'],true)['status'];

        if ($status == '1') {
            return view('pages.refund',compact('data'));
        }
        return redirect()->route('about-us');
    }

    public function cancellation_policy()
    {
        $data = BusinessSetting::where(['key' => 'cancellation_page'])->first();
        $status = json_decode($data['value'],true)['status'];

        if ($status == '1') {
            return view('pages.cancellation-policy', compact('data'));
        }
        return redirect()->route('about-us');
    }
}

