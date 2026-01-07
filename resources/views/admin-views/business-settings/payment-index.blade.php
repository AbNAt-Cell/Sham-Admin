@extends('layouts.admin.app')

@section('title', translate('Payment Setup'))

@section('content')
    <div class="content container-fluid">
        <div class="d-flex flex-wrap gap-2 align-items-center mb-4">
            <h2 class="h1 mb-0 d-flex align-items-center gap-2">
                <img width="20" class="avatar-img" src="{{asset('public/assets/admin/img/icons/third-party.png')}}" alt="">
                <span class="page-header-title">
                    {{translate('third_party')}}
                </span>
            </h2>
        </div>

        @include('admin-views.business-settings.partials._3rdparty-inline-menu')

        @php($partial_payment=\App\CentralLogics\Helpers::get_business_settings('partial_payment'))
        @php($combine_with=\App\CentralLogics\Helpers::get_business_settings('partial_payment_combine_with'))

        <div class="g-2">
            <form action="{{route('admin.business-settings.web-app.payment-method-status')}}" method="post">
                @csrf
                <div class="card">
                    <div class="card-body">
                        <div class="row mb-3">
                            <div class="col-md-4">
                                @php($cod=\App\CentralLogics\Helpers::get_business_settings('cash_on_delivery'))
                                <div class="form-control cmn_focus d-flex justify-content-between align-items-center gap-3">
                                    <label class="text-dark mb-0">{{translate('Cash On Delivery')}}</label>
                                    <label class="switcher">
                                        <input class="switcher_input check-offline-combination" data-method="COD" type="checkbox" name="cash_on_delivery" {{$cod == null || $cod['status'] == 0? '' : 'checked'}} id="cash_on_delivery_btn" tabindex="1">
                                        <span class="switcher_control"></span>
                                    </label>
                                </div>
                            </div>
                            <div class="col-md-4">
                                @php($dp=\App\CentralLogics\Helpers::get_business_settings('digital_payment'))
                                <div class="form-control cmn_focus d-flex justify-content-between align-items-center gap-3">
                                    <label class="text-dark mb-0">{{translate('Digital Payment')}}</label>
                                    <label class="switcher">
                                        <input class="switcher_input check-offline-combination" data-method="digital_payment" type="checkbox" name="digital_payment" {{$dp == null || $dp['status'] == 0? '' : 'checked'}}
                                           id="digital_payment_btn" tabindex="2">
                                        <span class="switcher_control"></span>
                                    </label>
                                </div>
                            </div>
                            <div class="col-md-4">
                                @php($op=\App\CentralLogics\Helpers::get_business_settings('offline_payment'))
                                <div class="form-control cmn_focus d-flex justify-content-between align-items-center gap-3">
                                    <label class="text-dark mb-0">{{translate('Offline Payment')}}</label>
                                    <label class="switcher">
                                        <input class="switcher_input check-offline-combination" data-method="offline_payment" type="checkbox" name="offline_payment" {{$op == null || $op['status'] == 0? '' : 'checked'}} id="offline_payment_btn" tabindex="3">
                                        <span class="switcher_control"></span>
                                    </label>
                                </div>
                            </div>

                        </div>

                        <div class="btn--container mt-2">
                            <button type="submit" class="btn btn-primary" tabindex="4">{{translate('save')}}</button>
                        </div>
                    </div>
                </div>

            </form>

        </div>

        <div class="digital_payment_section">
            <div class="row g-2">
                @if($published_status == 1)
                    <div class="col-12 mb-3">
                        <div class="card">
                            <div class="card-body d-flex justify-content-around">
                                <h4 class="text-danger pt-4">
                                    <i class="tio-info-outined"></i>
                                    {{ translate('Your current payment settings are disabled, because you have enabled
                                    payment gateway addon, To visit your currently active payment gateway settings please follow
                                    the link.') }}
                                </h4>
                                <span>
                            <a href="{{!empty($payment_url) ? $payment_url : ''}}" class="btn btn-outline-primary"><i class="tio-settings mr-1"></i>{{translate('settings')}}</a>
                        </span>
                            </div>
                        </div>
                    </div>
                @endif
            </div>

            <div class="row digital_payment_methods mt-3 g-3" id="payment-gatway-cards">
                @foreach($data_values as $payment)
                    <div class="col-md-6 mb-5">
                        <div class="card">
                            <form action="{{env('APP_MODE')!='demo'?route('admin.business-settings.web-app.payment-config-update'):'javascript:'}}" method="POST"
                                  id="{{$payment->key_name}}-form" enctype="multipart/form-data">
                                @csrf
                                <div class="card-header d-flex flex-wrap align-content-around">
                                    <h5>
                                        <span class="text-uppercase">{{str_replace('_',' ',$payment->key_name)}}</span>
                                    </h5>
                                    <label class="switch--custom-label cmn_focus-shadow rounded-pill p-1 toggle-switch toggle-switch-sm d-inline-flex">
                                        <span class="mr-2 switch--custom-label-text text-primary on text-uppercase">on</span>
                                        <span class="mr-2 switch--custom-label-text off text-uppercase">off</span>
                                        <input type="checkbox" name="status" value="1"
                                               class="toggle-switch-input"  {{$payment['is_active']==1?'checked':''}}>
                                        <span class="toggle-switch-label text rounded-pill">
                                            <span class="toggle-switch-indicator"></span>
                                        </span>
                                    </label>
                                </div>

                                @php($additional_data = $payment['additional_data'] != null ? json_decode($payment['additional_data']) : [])
                                <div class="card-body">
                                    <div class="payment--gateway-img">
                                        <img style="height: 80px"
                                             src="{{asset('storage/app/public/payment_modules/gateway_image')}}/{{$additional_data != null ? $additional_data->gateway_image : ''}}"
                                             onerror="this.src='{{asset('public/assets/admin/img/placeholder.png')}}'"
                                             alt="public">
                                    </div>

                                    <input name="gateway" value="{{$payment->key_name}}" class="d-none">

                                    @php($mode=$data_values->where('key_name',$payment->key_name)->first()->live_values['mode'])
                                    <div class="form-floating" style="margin-bottom: 10px">
                                        <select class="js-select form-control theme-input-style w-100" name="mode" >
                                            <option value="live" {{$mode=='live'?'selected':''}}>{{ translate('live') }}</option>
                                            <option value="test" {{$mode=='test'?'selected':''}}>{{ translate('test') }}</option>
                                        </select>
                                    </div>

                                    @php($supportedCountry = $data_values->where('key_name',$payment->key_name)->first()->live_values)
                                    @if (isset($supportedCountry['supported_country']))
                                        @php($supportedCountry = $supportedCountry['supported_country'])
                                        <label for="{{ $payment->key_name }}-title" class="form-label">{{translate('supported_country')}} *</label>
                                        <div class="mb-2" >
                                            <select class="js-select form-control w-100" name="supported_country" >
                                                <option value="egypt" {{$supportedCountry == 'egypt'?'selected':''}}>{{ translate('Egypt') }}</option>
                                                <option value="PAK" {{$supportedCountry == 'PAK'?'selected':''}}>{{ translate('Pakistan') }}</option>
                                                <option value="KSA" {{$supportedCountry == 'KSA'?'selected':''}}>{{ translate('Saudi Arabia') }}</option>
                                                <option value="oman" {{$supportedCountry == 'oman'?'selected':''}}>{{ translate('Oman') }}</option>
                                                <option value="UAE" {{$supportedCountry == 'UAE'?'selected':''}}>{{ translate('UAE') }}</option>
                                            </select>
                                        </div>
                                    @endif

                                    @if($payment->key_name === 'paystack')
                                        @php($skip=['gateway', 'mode', 'status', 'supported_country', 'callback_url'])
                                    @else
                                        @php($skip=['gateway','mode','status', 'supported_country'])
                                    @endif

                                    @foreach($data_values->where('key_name',$payment->key_name)->first()->live_values as $key=>$value)
                                        @if(!in_array($key,$skip))
                                            <div class="form-floating mb-3">
                                                <label for="exampleFormControlInput1"
                                                       class="form-label">{{ucwords(str_replace('_',' ',$key))}}
                                                    *</label>
                                                <input type="text" class="form-control"
                                                       name="{{$key}}"
                                                       placeholder="{{ucwords(str_replace('_',' ',$key))}} *"
                                                       value="{{env('APP_MODE')=='demo'?'':$value}}" >
                                            </div>
                                        @endif
                                    @endforeach

                                    <div class="form-floating mb-3">
                                        <label for="exampleFormControlInput1"
                                               class="form-label">{{translate('payment_gateway_title')}}</label>
                                        <input type="text" class="form-control"
                                               name="gateway_title"
                                               placeholder="{{translate('payment_gateway_title')}}"
                                               value="{{$additional_data != null ? $additional_data->gateway_title : ''}}" >
                                    </div>

                                    <div class="form-floating mb-3">
                                        <label for="exampleFormControlInput1"
                                               class="form-label">{{translate('choose logo')}}</label>
                                        <input type="file" class="form-control" name="gateway_image" accept=".jpg, .png, .jpeg|image/*" >
                                    </div>

                                    <div class="text-right mt-4">
                                        <button type="{{env('APP_MODE')!='demo'?'submit':'button'}}"
                                                class="btn btn-primary px-5 call-demo" >{{translate('save')}}</button>
                                    </div>
                                </div>
                            </form>
                        </div>
                    </div>
                @endforeach
            </div>
        </div>
    </div>

    <div class="modal fade" id="offlinePaymentWarningModal" tabindex="-1" aria-labelledby="modalLabel" aria-hidden="true">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <button type="button" class="close" data-dismiss="modal" aria-label="Close">
                        <span aria-hidden="true">&times;</span>
                    </button>
                </div>
                <div class="modal-body">
                    <div class="text-center">
                        <div class="my-4">
                            <img src="{{ asset('public/assets/admin/svg/components/info.svg') }}" alt="Checked Icon">
                        </div>
                        <div class="my-4">
                            <h4>{{ translate('Offline Payment Warning') }}</h4>
                            <p> {{ translate('Since offline payment is combined with this payment method, you should change that before disabling it from') }} <a href="{{ route('admin.business-settings.restaurant.restaurant-setup') }}" target="_blank">{{ translate('Business Setup') }}</a> </p>
                        </div>
                        <div class="my-4">
                            <button type="button" class="btn btn-primary" data-dismiss="modal">OK</button>
                        </div>
                    </div>
                </div>
            </div>

        </div>
    </div>

@endsection

@push('script_2')
    <script>

        $(document).on('change', '.check-offline-combination', function () {
            let method = $(this).data('method');
            let status = $(this).prop('checked');
            let partialPaymentStatus = "{{ $partial_payment }}";
            let partialCombineWith = "{{ $combine_with }}";
            let $checkbox = $(this); // Store reference to the checkbox

            console.log(partialPaymentStatus)

            if (partialPaymentStatus == '1') {
                if ((partialCombineWith === method || partialCombineWith === 'all') && status === false) {
                    // Show Bootstrap modal
                    $('#offlinePaymentWarningModal').modal('show');

                    // Revert the checkbox state after showing the modal
                    setTimeout(() => {
                        $checkbox.prop('checked', true); // Reset to checked
                    }, 300);
                }
            }
        });


        $(document).on('change', 'input[name="gateway_image"]', function () {
            var $input = $(this);
            var $form = $input.closest('form');
            var gatewayName = $form.attr('id');

            if (this.files && this.files[0]) {
                var reader = new FileReader();
                var $imagePreview = $form.find('.payment--gateway-img img'); // Find the img element within the form

                reader.onload = function (e) {
                    $imagePreview.attr('src', e.target.result);
                }

                reader.readAsDataURL(this.files[0]);
            }
        });

    </script>

    <script>
        @if($published_status == 1)
            $('#payment-gatway-cards').find('input').each(function(){
                $(this).attr('disabled', true);
            });
            $('#payment-gatway-cards').find('select').each(function(){
                $(this).attr('disabled', true);
            });
            $('#payment-gatway-cards').find('.switcher_input').each(function(){
                $(this).removeAttr('checked', true);
            });
            $('#payment-gatway-cards').find('button').each(function(){
                $(this).attr('disabled', true);
            });
        @endif
    </script>
@endpush
