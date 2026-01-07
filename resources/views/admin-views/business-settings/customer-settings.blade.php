@extends('layouts.admin.app')

@section('title', translate('Business Settings'))

@section('content')
    <div class="content container-fluid">
        <div class="d-flex flex-wrap gap-2 align-items-center mb-4">
            <h2 class="h1 mb-0 d-flex align-items-center gap-2">
                <img width="20" class="avatar-img" src="{{asset('public/assets/admin/img/icons/business_setup2.png')}}" alt="">
                <span class="page-header-title">
                    {{translate('business_setup')}}
                </span>
            </h2>
        </div>

        @include('admin-views.business-settings.partials._business-setup-inline-menu')

        <form action="{{ route('admin.business-settings.restaurant.customer.settings.update') }}" method="post" id="update-settings">
            @csrf

            <div class="card mb-3 view-details-container">
                <div class="card-body">
                    <div class="row align-items-center">
                        <div class="col-xxl-8 col-md-6 mb-md-0 mb-2">
                            <h4 class="mb-1 fz-16">{{ translate('Customer Wallet') }}</h4>
                            <p class="mb-0 fz-12">{{ translate('When active this feature customer can Earn and Buy through wallet. See customer wallet from Customers Details page.') }}</p>
                        </div>
                        <div class="col-xxl-4 col-md-6">
                            <div class="d-flex flex-sm-nowrap flex-wrap justify-content-end justify-content-end align-items-center gap-sm-3 gap-2">
                                <div class="customer-view-btn view-btn  order-sm-0 order-3 fz-12 cursor-pointer font-weight-semibold d-flex align-items-center gap-1">
                                    {{ translate('View') }}
                                    <i class="tio-down-ui fz-12"></i>
                                </div>
                                <div class="form-group mb-0">
                                    <label class="toggle-switch toggle-switch-sm" for="customer_wallet">
                                        <input type="checkbox" class="toggle-switch-input section-toggle" name="customer_wallet" id="customer_wallet" value="1"
                                            {{ isset($data['wallet_status']) && $data['wallet_status'] == 1 ? 'checked' : '' }}>
                                        <span class="toggle-switch-label text">
                                            <span class="toggle-switch-indicator"></span>
                                        </span>
                                    </label>
                                </div>
                            </div>
                        </div>
                    </div>
                    <div class="bg-color rounded mt-3 view-details customer-hide-wrap">
                        <div class="card-body">
                            <div class="row g-lg-3 g-2 align-items-center">
                                <div class="col-xxl-3 col-lg-5">
                                    <span class="fz-14 black-color mb-1 d-block">{{ translate('Add Fund to Wallet') }}</span>
                                    <p class="fz-12 text-c mb-0">{{ translate('You can add funds to your wallet to make quick and easy payments within the app') }}</p>
                                </div>
                                <div class="col-xxl-9 col-lg-7">
                                    <div class="form-group m-0  bg-white p-20 rounded">
                                        <label class="toggle-switch toggle-switch-sm d-flex justify-content-between border rounded px-4 form-control" for="add_fund_to_wallet">
                                            <span class="pr-2">{{ translate('Status') }}</span>
                                            <input type="checkbox" class="toggle-switch-input" name="add_fund_to_wallet" id="add_fund_to_wallet" value="1"
                                                {{ isset($data['add_fund_to_wallet']) && $data['add_fund_to_wallet'] == 1 ? 'checked' : '' }}>
                                            <span class="toggle-switch-label text">
                                                <span class="toggle-switch-indicator"></span>
                                            </span>
                                        </label>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <div class="card mb-3 view-details-container">
                <div class="card-body wrapper">
                    <div class="row align-items-center">
                        <div class="col-xxl-8 col-md-6 mb-md-0 mb-2">
                            <h4 class="mb-1 fz-16">{{ translate('Customer Loyalty Point') }}</h4>
                            <p class="mb-0 fz-12">{{ translate('If enabled customers will earn a certain amount of points after each purchase.') }}</p>
                        </div>
                        <div class="col-xxl-4 col-md-6">
                            <div class="d-flex flex-sm-nowrap flex-wrap justify-content-sm-end justify-content-end align-items-center gap-sm-3 gap-2">
                                <div class="customer-view-btn view-btn order-sm-0 order-3 fz-12 cursor-pointer font-weight-semibold d-flex align-items-center gap-1">
                                    {{ translate('View') }}
                                    <i class="tio-down-ui fz-12"></i>
                                </div>

                                <div class="form-group mb-0">
                                    <label class="toggle-switch toggle-switch-sm" for="customer_loyalty_point">
                                        <input type="checkbox" class="toggle-switch-input section-toggle"
                                               name="customer_loyalty_point"
                                               id="customer_loyalty_point"
                                               value="1"
                                            {{ isset($data['loyalty_point_status']) && $data['loyalty_point_status'] == 1 ? 'checked' : '' }}>
                                        <span class="toggle-switch-label text">
                                            <span class="toggle-switch-indicator"></span>
                                        </span>
                                    </label>
                                </div>
                            </div>
                        </div>
                    </div>
                    <div class="bg-color rounded mt-3 view-details customer-hide-wrap">
                        <div class="card-body">
                            <div class="row g-3">
                                <div class="col-sm-6 col-lg-4">
                                    <div class="form-group m-0">
                                        <label class="input-label" for="loyalty_point_exchange_rate">{{ translate('1')}} {{ \App\CentralLogics\Helpers::currency_symbol() }} {{ translate('Equal to How Much Loyalty Points?') }}
                                            <i class="tio-info text-muted" data-toggle="tooltip" data-placement="top" title="{{ translate('It’s the number of points equal in value to 1') }} {{ \App\CentralLogics\Helpers::currency_code() }}"></i>
                                        </label>
                                        <input type="number" class="form-control" name="loyalty_point_exchange_rate" value="{{ $data['loyalty_point_exchange_rate'] ?? '0' }}">
                                    </div>
                                </div>
                                <div class="col-sm-6 col-lg-4">
                                    <div class="form-group m-0">
                                        <label class="input-label">{{ translate('Percentage of Loyalty Point on Order Amount') }}
                                            <i class="tio-info text-muted" data-toggle="tooltip" data-placement="top" title="{{ translate('Setup loyalty point percentage earned by customer based on order amount') }}"></i>
                                        </label>
                                        <input type="number" class="form-control" name="item_purchase_point" step=".01"
                                            value="{{ $data['loyalty_point_item_purchase_point'] ?? '0' }}">
                                    </div>
                                </div>
                                <div class="col-sm-6 col-lg-4">
                                    <div class="form-group m-0">
                                        <label class="input-label">{{ translate('Minimum Loyalty Points to Transfer Into Wallet') }}
                                            <i class="tio-info text-muted" data-toggle="tooltip" data-placement="top" title="{{ translate('This point is the required amount which is needed to convert the point to the wallet balance') }}"></i>
                                        </label>
                                        <input type="number" class="form-control" name="loyalty_point_minimum_point" min="0"
                                            value="{{ $data['loyalty_point_minimum_point'] ?? '0' }}">
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <div class="card mb-3 view-details-container">
                <div class="card-body wrapper">
                    <div class="row align-items-center">
                        <div class="col-xxl-8 col-md-6 mb-md-0 mb-2">
                            <h4 class="mb-1 fz-16">{{ translate('Customer Referral Earning Settings') }}</h4>
                            <p class="mb-0 fz-12">{{ translate('Customers will receive this wallet balance rewards for sharing their referral code') }}</p>
                        </div>
                        <div class="col-xxl-4 col-md-6">
                            <div class="d-flex flex-sm-nowrap flex-wrap justify-content-sm-end justify-content-end align-items-center gap-sm-3 gap-2">
                                <div class="customer-view-btn view-btn order-sm-0 order-3 fz-12 cursor-pointer font-weight-semibold d-flex align-items-center gap-1">
                                    {{ translate('View') }}
                                    <i class="tio-down-ui fz-12"></i>
                                </div>
                                <div class="form-group mb-0">
                                    <label class="toggle-switch toggle-switch-sm" for="referral_earning">
                                        <input type="checkbox" class="toggle-switch-input section-toggle" name="ref_earning_status" id="referral_earning" value="1"
                                            {{ isset($data['ref_earning_status']) && $data['ref_earning_status'] == 1 ? 'checked' : '' }}>

                                        <span class="toggle-switch-label text">
                                            <span class="toggle-switch-indicator"></span>
                                        </span>
                                    </label>
                                </div>
                            </div>
                        </div>
                    </div>
                    <div class="mt-3 view-details customer-hide-wrap">
                        <div class="bg-color rounded mb-3">
                            <div class="card-body">
                                <div class="row g-lg-3 g-2 align-items-center">
                                    <div class="col-xxl-3 col-lg-5">
                                        <span class="fz-14 black-color mb-1 d-block">{{ translate('Who Share the Code') }}</span>
                                        <p class="fz-12 text-c mb-0">{{ translate('Customers will receive this wallet balance rewards for sharing their referral code with friends who use the code when signing up and completing their first order.') }}</p>
                                    </div>
                                    <div class="col-xxl-9 col-lg-7">
                                        <div class="form-group m-0 bg-white p-20 rounded">
                                            <label class="input-label fw-normal text-muted fz-14" for="referrer_earning_exchange_rate">{{ translate('Earning Per Referral')}} ({{\App\CentralLogics\Helpers::currency_symbol()}})
                                                <i class="tio-info text-muted" data-toggle="tooltip" data-placement="top" title="{{ translate('Set the reward amount customers will receive for sharing their referral code.') }}"></i>
                                            </label>
                                            <input type="number" step=0.01" class="form-control mb-1" name="ref_earning_exchange_rate" value="{{ $data['ref_earning_exchange_rate'] ?? '0' }}">
                                            <span class="text-c1 fz-12">{{ translate('Must Turn on') }} <strong>{{ translate('Add Fund to Wallet') }}</strong> {{ translate('option, otherwise customer can’t receive the reward amount.') }}</span>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                        <div class="bg-color rounded">
                            <div class="card-body">
                                <div class="row g-lg-3 g-2 align-items-center">
                                    <div class="col-xxl-3 col-lg-5">
                                        <span class="fz-14 black-color mb-1 d-block">{{ translate('Who Use the Code') }}</span>
                                        <p class="fz-12 text-c mb-0">{{ translate('By applying the referral code during signup and when making their first purchase customers will enjoy a discount for a limited time.') }}</p>
                                    </div>
                                    <div class="col-xxl-9 col-lg-7">
                                        <div class="bg-white p-20 rounded">
                                            <div class="form-group m-0 ">
                                                <span class="d-block mb-2">{{ translate('Customer will Get Discount on First Order') }}</span>
                                                <label class="toggle-switch toggle-switch-sm d-flex justify-content-between border rounded px-4 form-control" for="customer_referred_discount_status">
                                                    <span class="pr-2">{{ translate('Status') }}</span>
                                                    <input type="checkbox" class="toggle-switch-input" name="customer_referred_discount_status" id="customer_referred_discount_status" value="1"
                                                        {{ isset($data['customer_referred_discount_status']) && $data['customer_referred_discount_status'] == 1 ? 'checked' : '' }}>
                                                    <span class="toggle-switch-label text">
                                                        <span class="toggle-switch-indicator"></span>
                                                    </span>
                                                </label>
                                            </div>
                                            <div class="customer-status-order-hideails row g-lg-3 g-2 mt-2">
                                                <div class="col-lg-6">
                                                    <label class="input-label fw-normal text-muted fz-14" for="">{{ translate('Discount Amount') }}
                                                        <i class="tio-info text-muted" data-toggle="tooltip" data-placement="top" title="{{ translate('Set the discount amount for customers who apply the referral code.') }}"></i>
                                                    </label>
                                                    <div class="d-flex border rounded w-100 overflow-hidden">
                                                        <input type="number" class="form-control border-0" name="customer_referred_discount_amount" value="{{ $data['customer_referred_discount_amount'] }}" min="0">
                                                        <div>
                                                            <select name="customer_referred_discount_type" id="" class="bg-color px-2 border-0 h-100">
                                                                <option value="percent" {{ $data['customer_referred_discount_type'] == 'percent' ? 'selected' : ''}}>%</option>
                                                                <option value="amount" {{ $data['customer_referred_discount_type'] == 'amount' ? 'selected' : ''}}>{{ \App\CentralLogics\Helpers::currency_symbol() }}</option>
                                                            </select>
                                                        </div>
                                                    </div>
                                                </div>
                                                <div class="col-lg-6">
                                                    <label class="input-label fw-normal text-muted fz-14" for="">{{ translate('Validity') }}
                                                        <i class="tio-info text-muted" data-toggle="tooltip" data-placement="top" title="{{ translate('Set the referral code’s validity period for customers who apply it.') }}"></i>
                                                    </label>
                                                    <div class="d-flex border rounded w-100 overflow-hidden">
                                                        <input type="number" class="form-control border-0" name="customer_referred_validity_value" value="{{ $data['customer_referred_validity_value'] }}" min="0">
                                                        <div>
                                                            <select class="bg-color px-2 border-0 h-100" name="customer_referred_validity_type" id="">
                                                                <option value="day" {{ $data['customer_referred_validity_type'] == 'day' ? 'selected' : ''}}>{{ translate('Day') }}</option>
                                                                <option value="week" {{ $data['customer_referred_validity_type'] == 'week' ? 'selected' : ''}}>{{ translate('Week') }}</option>
                                                                <option value="month" {{ $data['customer_referred_validity_type'] == 'month' ? 'selected' : ''}}>{{ translate('Month') }}</option>
                                                            </select>
                                                        </div>
                                                    </div>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <div class="btn--container">
                <button type="{{env('APP_MODE')!='demo'?'submit':'button'}}"
                        class="btn btn-primary call-demo">{{translate('Save')}}</button>
            </div>
        </form>
    </div>
@endsection

@push('script_2')

    <script>
        $(document).ready(function () {
            // View button toggles visibility manually
            $(".view-btn").on("click", function () {
                var container = $(this).closest(".view-details-container");
                var details = container.find(".view-details");
                var icon = $(this).find("i");

                $(this).toggleClass("active");
                details.slideToggle(300);
                icon.toggleClass("rotate-180deg");
            });

            // On checkbox toggle, show/hide the relevant section
            $(".section-toggle").on("change", function () {
                var container = $(this).closest(".view-details-container");
                var details = container.find(".view-details");

                if ($(this).is(':checked')) {
                    details.slideDown(300);
                } else {
                    details.slideUp(300);
                }
            });

            // ✅ On page load, show/hide each .view-details based on checked status
            $(".section-toggle").each(function () {
                var container = $(this).closest(".view-details-container");
                var details = container.find(".view-details");

                if ($(this).is(':checked')) {
                    details.show(); // Show instantly
                } else {
                    details.hide(); // Hide instantly
                }
            });
        });
    </script>

@endpush
