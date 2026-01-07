<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>@yield('title')</title>

    @php($icon = \App\Model\BusinessSetting::where(['key' => 'fav_icon'])->first()->value??'')

    <link rel="shortcut icon" href="{{ asset('storage/app/public/restaurant/' . $icon ?? '') }}">

    <link href="https://fonts.googleapis.com/css2?family=Open+Sans:wght@400;600&amp;display=swap" rel="stylesheet">
    <link rel="stylesheet" href="{{asset('public/assets/admin')}}/css/vendor.min.css">

    <link rel="stylesheet" href="{{asset('public/assets/admin')}}/css/theme.minc619.css?v=1.0">
    <link rel="stylesheet" href="{{asset('public/assets/admin')}}/css/style.css">
</head>

<body>
<section class="py-5 bg-black">

    <?php
        $pageNames = \App\Model\BusinessSetting::whereIn('key', ['refund_page', 'return_page', 'cancellation_page'])
            ->pluck('value', 'key')
            ->toArray();

        $returnPage = isset($pageNames['return_page']) ? json_decode($pageNames['return_page'], true) : null;
        $refundPage = isset($pageNames['refund_page']) ? json_decode($pageNames['refund_page'], true) : null;
        $cancellationPage = isset($pageNames['cancellation_page']) ? json_decode($pageNames['cancellation_page'], true) : null;

        $logoName = \App\CentralLogics\Helpers::get_business_settings('logo');
        $logo = \App\CentralLogics\Helpers::onErrorImage($logoName, asset('storage/app/public/restaurant') . '/' . $logoName, asset('public/assets/admin/img/160x160/img2.jpg'), 'restaurant/');
    ?>
    <div class="container">
        <div class="inline-page-menu mt-4 d-flex justify-content-between gap-3 flex-wrap">
            <div class="flex-grow-1">
                <img width="100" height="100" src="{{ $logo }}" alt="{{ translate('logo') }}">
            </div>
            <div>
                <ul class="list-unstyled">
                    <li class="{{Request::is('about-us')? 'active': ''}}"><a href="{{route('about-us')}}">{{translate('About Us')}}</a></li>
                    <li class="{{Request::is('terms-and-conditions')? 'active': ''}}"><a href="{{route('terms-and-conditions')}}">{{translate('Terms and Condition')}}</a></li>
                    <li class="{{Request::is('privacy-policy')? 'active': ''}}"><a href="{{route('privacy-policy')}}">{{translate('Privacy Policy')}}</a></li>
                   @if($returnPage && isset($returnPage['status']) && $returnPage['status'] == 1)
                        <li class="{{Request::is('return-policy')? 'active': ''}}"><a href="{{route('return-policy')}}">{{translate('Return Policy')}}</a></li>
                   @endif
                    @if($refundPage && isset($refundPage['status']) && $refundPage['status'] == 1)
                        <li class="{{Request::is('refund-policy')? 'active': ''}}"><a href="{{route('refund-policy')}}">{{translate('Refund Policy')}}</a></li>
                   @endif
                    @if($cancellationPage && isset($cancellationPage['status']) && $cancellationPage['status'] == 1)
                        <li class="{{Request::is('cancellation-policy')? 'active': ''}}"><a href="{{route('cancellation-policy')}}">{{translate('Cancellation Policy')}}</a></li>
                   @endif
                </ul>
            </div>
        </div>
        @yield('content')

    </div>
</section>
</body>

{!! Toastr::message() !!}

</html>
