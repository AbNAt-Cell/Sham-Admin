@extends('layouts.admin.app')

@section('title', translate('Product Preview'))

@push('css_or_js')
    <link rel="stylesheet" href="{{asset('/public/assets/admin/css/lightbox.min.css')}}">
@endpush

@section('content')
    <div class="content container-fluid">
        <div class="d-flex flex-wrap justify-content-between gap-2 align-items-center mb-4">
            <h2 class="h1 mb-0 d-flex align-items-center gap-2">
                <img width="20" class="avatar-img" src="{{asset('public/assets/admin/img/icons/bulk_import.png')}}" alt="">
                <span class="page-header-title">
                    {{ Str::limit($product['name'], 30) }}
                </span>
            </h2>

            <div class="d-flex align-items-center flex-wrap gap-2">

                <!-- Delete Button -->
                <button type="button" class="btn btn-outline-danger btn-sm delete form-alert"
                        data-id="product-{{$product['id']}}"
                        data-message="{{translate('Want to delete this item ?')}}">
                    <i class="tio-delete"></i> {{ translate('Delete') }}
                </button>
                <form action="{{route('admin.product.delete',[$product['id']])}}" method="post" id="product-{{$product['id']}}">
                    @csrf @method('delete')
                </form>

                <!-- Recommended Toggle -->
                <div class="d-flex align-items-center px-2 py-1 bg-light rounded">
                    <span class="mr-2">{{ translate('Recommended') }}</span>
                    <label class="switcher mb-0">
                        <input id="recommended-{{$product['id']}}" class="switcher_input recommended-status-change" type="checkbox"
                               {{$product['is_recommended']==1? 'checked' : ''}}
                               data-url="{{route('admin.product.recommended',[$product['id'],0])}}">
                        <span class="switcher_control"></span>
                    </label>
                </div>

                <!-- Availability Toggle -->
                <div class="d-flex align-items-center px-2 py-1 bg-light rounded">
                    <span class="mr-2">{{ translate('Availability') }}</span>
                    <label class="switcher mb-0">
                        <input id="{{$product['id']}}" class="switcher_input status-change" type="checkbox"
                               {{$product['status']==1? 'checked' : ''}}
                               data-url="{{route('admin.product.status',[$product['id'],0])}}">
                        <span class="switcher_control"></span>
                    </label>
                </div>

                <!-- Edit Button -->
                <a href="{{route('admin.product.edit',[$product['id']])}}" class="btn btn-danger">
                    <i class="tio-edit"></i> {{ translate('Edit Product') }}
                </a>
            </div>
        </div>

        <div class="card mb-3">
            <div class="card-body">
                <div class="row align-items-md-center g-lg-3 g-2">
                    <div class="col-xxl-8 col-lg-8">
                        <div class="d-flex align-items-start flex-sm-nowrap flex-wrap gap-4">
                            <img class="avatar avatar-xxl avatar-4by3" src="{{$product['imageFullPath']}}" alt="Image Description">
                            <div class="card w-100">
                                <div class="card-body">
                                    @php($data = Helpers::get_business_settings('language'))
                                    @php($defaultLang = Helpers::get_default_language())

                                    @if($data && array_key_exists('code', $data[0]))
                                        <ul class="nav nav-tabs w-fit-content mb-4">
                                            @foreach($data as $lang)
                                                <li class="nav-item">
                                                    <a class="nav-link lang_link {{$lang['code'] == 'en'? 'active':''}}" href="#" id="{{$lang['code']}}-link">{{Helpers::get_language_name($lang['code']).'('.strtoupper($lang['code']).')'}}</a>
                                                </li>
                                            @endforeach
                                        </ul>

                                        @foreach($data as $lang)
                                                <?php
                                                if(count($product['translations'])){
                                                    $translate = [];
                                                    foreach($product['translations'] as $t)
                                                    {
                                                        if($t->locale == $lang['code'] && $t->key=="name"){
                                                            $translate[$lang['code']]['name'] = $t->value;
                                                        }
                                                        if($t->locale == $lang['code'] && $t->key=="description"){
                                                            $translate[$lang['code']]['description'] = $t->value;
                                                        }
                                                    }
                                                }
                                                ?>
                                            <div class="{{$lang['code'] != 'en'? 'd-none':''}} lang_form" id="{{$lang['code']}}-div">
                                                <div class="mb-2">
                                                    <h3 class="mb-0">{{$translate[$lang['code']]['name'] ?? $product['name']}}</h3>
                                                </div>

                                                <div class="mb-2">
                                                    <span class="badge badge-soft-secondary fz-12 px-3 py-2 text-title">
                                                        <img width="13" class="mr-1" src="{{asset('public/assets/admin/img/icons/leaf.svg')}}">{{ translate($product->product_type) }}
                                                    </span>
                                                    @if($product['halal_status'])
                                                        <span class="badge badge-soft-secondary fz-12 px-3 py-2 text-title">
                                                            <img width="13" class="mr-1" src="{{asset('public/assets/admin/img/halal-tags.png')}}">{{ translate("Halal") }}
                                                        </span>
                                                    @endif
                                                </div>

                                                <div class="mb-2">
                                                    <h5 class="mb-1">{{ translate('Description') }}:</h5>
                                                    <p class="fz-12 mb-0">{{$translate[$lang['code']]['description'] ?? $product['description']}}</p>
                                                </div>
                                            </div>
                                        @endforeach
                                    @else
                                        <div id="english-div">
                                            <div class="mb-2">
                                                <h5 class="font-weight-bold mb-1">{{translate('name')}} (EN)</h5>
                                                <div class="p-3 bg-light rounded">
                                                    <h4 class="mb-0">{{$product['name']}}</h4>
                                                </div>
                                            </div>
                                            <div class="mb-2">
                                                    <span class="badge badge-soft-secondary fz-12 px-3 py-2 text-title">
                                                        <img width="13" class="mr-1" src="{{asset('public/assets/admin/img/icons/leaf.svg')}}">{{ translate($product->product_type) }}
                                                    </span>
                                                @if($product['halal_status'])
                                                    <span class="badge badge-soft-secondary fz-12 px-3 py-2 text-title">
                                                        <img width="13" class="mr-1" src="{{asset('public/assets/admin/img/halal-tags.png')}}">{{ translate("Halal") }}
                                                    </span>
                                                @endif
                                            </div>

                                            <div class="mb-2">
                                                <h5 class="mb-1">{{ translate('Description') }} : </h5>
                                                <p class="fz-12 mb-0">{{ $product['description']}} }}</p>
                                            </div>
                                        </div>
                                    @endif
                                </div>
                            </div>

                        </div>
                    </div>

                    <div class="col-xxl-4 col-lg-4">
                        <ul class="list-unstyled list-unstyled-py-2 mb-0 bg-color rounded pt-lg-0 pt-2 pb-3 px-3">
                            <div class="d-flex align-items-center review-counting-wrap gap-3 mb-2">
                                <h4 class="fz-34 text-c1  mb-0">
                                    <i class="tio-star fz-34 mb-3"></i><span class="c1">{{count($product->rating)>0?number_format($product->rating[0]->average, 1, '.', ' '):0}}</span><span class="text-muted fz-20">/5</span>
                                </h4>
                                <p class="mb-0 left-line"> {{$product->reviews->count()}} {{translate('reviews')}}
                                    <span class="badge badge-soft-dark badge-pill ml-1"></span>
                                </p>
                            </div>
                            @php($total=$product->reviews->count())
                            <li class="d-flex align-items-center font-size-sm">
                                @php($five=\App\CentralLogics\Helpers::rating_count($product['id'],5))
                                <span
                                    class="progress-name text-c3">{{translate('Excellent')}}</span>
                                <div class="progress flex-grow-1">
                                    <div class="progress-bar" role="progressbar"
                                         style="width: {{$total==0?0:($five/$total)*100}}%;"
                                         aria-valuenow="{{$total==0?0:($five/$total)*100}}"
                                         aria-valuemin="0" aria-valuemax="100"></div>
                                </div>
                                <span class="ml-3">{{$five}}</span>
                            </li>
                            <li class="d-flex align-items-center font-size-sm">
                                @php($four=\App\CentralLogics\Helpers::rating_count($product['id'],4))
                                <span class="progress-name text-c3">{{translate('Good')}}</span>
                                <div class="progress flex-grow-1">
                                    <div class="progress-bar" role="progressbar"
                                         style="width: {{$total==0?0:($four/$total)*100}}%;"
                                         aria-valuenow="{{$total==0?0:($four/$total)*100}}"
                                         aria-valuemin="0" aria-valuemax="100"></div>
                                </div>
                                <span class="ml-3">{{$four}}</span>
                            </li>
                            <li class="d-flex align-items-center font-size-sm">
                                @php($three=\App\CentralLogics\Helpers::rating_count($product['id'],3))
                                <span class="progress-name text-c3">{{translate('Average')}}</span>
                                <div class="progress flex-grow-1">
                                    <div class="progress-bar" role="progressbar"
                                         style="width: {{$total==0?0:($three/$total)*100}}%;"
                                         aria-valuenow="{{$total==0?0:($three/$total)*100}}"
                                         aria-valuemin="0" aria-valuemax="100"></div>
                                </div>
                                <span class="ml-3">{{$three}}</span>
                            </li>
                            <li class="d-flex align-items-center font-size-sm">
                                @php($two=\App\CentralLogics\Helpers::rating_count($product['id'],2))
                                <span class="progress-name text-c3">{{translate('Below_Average')}}</span>
                                <div class="progress flex-grow-1">
                                    <div class="progress-bar" role="progressbar"
                                         style="width: {{$total==0?0:($two/$total)*100}}%;"
                                         aria-valuenow="{{$total==0?0:($two/$total)*100}}"
                                         aria-valuemin="0" aria-valuemax="100"></div>
                                </div>
                                <span class="ml-3">{{$two}}</span>
                            </li>
                            <li class="d-flex align-items-center font-size-sm">
                                @php($one=\App\CentralLogics\Helpers::rating_count($product['id'],1))
                                <span class="progress-name text-c3">{{translate('Poor')}}</span>
                                <div class="progress flex-grow-1">
                                    <div class="progress-bar" role="progressbar"
                                         style="width: {{$total==0?0:($one/$total)*100}}%;"
                                         aria-valuenow="{{$total==0?0:($one/$total)*100}}"
                                         aria-valuemin="0" aria-valuemax="100"></div>
                                </div>
                                <span class="ml-3">{{$one}}</span>
                            </li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>

        <div class="card mb-3">
            <div class="">
                <div class="table-responsive">
                    <table class="table table-borderless table-thead-bordered table-nowrap card-table">
                        <thead class="thead-light">
                            <tr>
                                <th class="bg-color">{{translate('General Info')}}</th>
                                <th class="bg-color">{{translate('Price Information')}}</th>
                                <th class="bg-color">{{translate('Availability & Stock')}}</th>
                                <th class="bg-color">{{translate('Cuisine')}}</th>
                                <th class="bg-color">{{translate('Addons')}}</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr>
                                <td>
                                    <div class="d-flex flex-column gap-2">
                                        <div class="d-flex align-items-center gap-1">
                                            <div class="min-w-100">{{ translate('Category') }}</div>
                                            : <strong> {{ $product?->category['name'] ?? \App\CentralLogics\translate('not_available')}}</strong>
                                        </div>
                                        @if($product?->subCategory)
                                            <div class="d-flex align-items-center gap-1">
                                                <div class="min-w-100">{{ translate('Sub Category') }}</div>
                                                : <strong class="text-capitalize">{{ $product?->subCategory['name'] }}</strong>
                                            </div>
                                        @endif
                                        <div class="d-flex align-items-center gap-1">
                                            <div class="min-w-100">{{ translate('Item Type') }}</div>
                                            : <strong class="text-capitalize">{{str_replace('_',' ', $product->product_type)}}</strong>
                                        </div>
                                    </div>
                                </td>
                                <td>
                                    <div class="d-flex flex-column gap-2">
                                        <div class="d-flex align-items-center gap-1">
                                            <div class="min-w-70">{{translate('Price')}} </div>
                                            : <strong> {{ \App\CentralLogics\Helpers::set_symbol($product['price']) }}</strong>
                                        </div>
                                        <div class="d-flex align-items-center gap-1">
                                            <div class="min-w-70">{{translate('Discount')}} </div>
                                            : <strong> {{ \App\CentralLogics\Helpers::set_symbol(\App\CentralLogics\Helpers::discount_calculate($product,$product['price'])) }}</strong>
                                        </div>
                                        <div class="d-flex align-items-center gap-1">
                                            <div class="min-w-70">{{translate('Tax')}} </div>
                                            : <strong> {{ \App\CentralLogics\Helpers::set_symbol(\App\CentralLogics\Helpers::new_tax_calculate($product,$product['price'], $discount_data)) }}</strong>
                                        </div>
                                    </div>
                                </td>
                                <td>
                                    <div class="d-flex flex-column gap-2">
                                        <div class="d-flex align-items-center gap-1">
                                            <div class="min-w-80">{{ translate('Stock Type') }}</div>
                                            : <strong>{{ ucfirst($product->main_branch_product?->stock_type) }}</strong>
                                        </div>
                                        @if(isset($product->main_branch_product) && $product->main_branch_product->stock_type != 'unlimited')
                                            <div class="d-flex align-items-center gap-1">
                                                <div class="min-w-80">{{ translate('Stock') }}</div>
                                                : <strong>{{ $product->main_branch_product->stock - $product->main_branch_product->sold_quantity }}</strong>
                                            </div>
                                        @endif
                                        <div class="d-flex align-items-center gap-1">
                                            <div class="min-w-80">{{ translate('Availability') }}</div>
                                            : <strong>{{date(config('time_format'), strtotime($product['available_time_starts']))}} - {{date(config('time_format'), strtotime($product['available_time_ends']))}}</strong>
                                        </div>
                                    </div>
                                </td>
                                <td>
                                    @foreach($product->cuisines as $cuisine)
                                        <strong class="text-capitalize">{{$cuisine?->name}} </strong> <br>
                                    @endforeach
                                </td>
                                <td>
                                    @foreach(\App\Model\AddOn::whereIn('id',json_decode($product['add_ons'],true))->get() as $addon)
                                        <div class="d-flex align-items-center gap-1">
                                            <div class="text-capitalize min-w-100">{{$addon['name']}}</div>
                                            : <strong> {{ \App\CentralLogics\Helpers::set_symbol($addon['price']) }} </strong>
                                        </div>
                                    @endforeach
                                </td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        @if (!empty(json_decode($product->variations, true)))
            <div class="card mb-3">
                <div class="">
                    <div class="table-responsive">
                        <table class="table table-borderless table-thead-bordered table-nowrap card-table">
                            <thead class="thead-light">
                            <tr>
                                <th class="bg-color">{{translate('SL')}}</th>
                                <th class="bg-color">{{translate('Variation Name')}}</th>
                                <th class="bg-color">{{translate('Variation Wise Price')}}</th>
                            </tr>
                            </thead>
                            <tbody>
                            @foreach(json_decode($product->variations,true) as $variation)
                                <tr>
                                    <td class="align-middle">
                                        {{ $loop->iteration }}
                                    </td>
                                    <td class="align-middle">
                                        <div class="d-block text-capitalize">
                                            <strong>{{$variation['name']}} -</strong>
                                            @if ($variation['type'] == 'multi')
                                                <span class="fz-12"> {{ translate('multiple_select') }}</span>
                                            @elseif($variation['type'] =='single')
                                                <span class="fz-12"> {{ translate('single_select') }}</span>
                                            @endif
                                            @if ($variation['required'] == 'on')
                                                <span class="fz-12"> ({{ translate('required') }})</span>
                                            @endif
                                            @if ($variation['min'] != 0 && $variation['max'] != 0)
                                                ({{ translate('Min_select') }}: {{ $variation['min'] }} - {{ translate('Max_select') }}: {{ $variation['max'] }})
                                            @endif
                                        </div>
                                        @if (isset($variation['values']))
                                            @foreach ($variation['values'] as $value)
                                                <span class="d-block text-capitalize">{{ $value['label']}}</span>
                                            @endforeach
                                        @endif
                                    </td>
                                    <td class="align-middle">
                                        @if (isset($variation['values']))
                                            @foreach ($variation['values'] as $value)
                                                <span class="d-block text-capitalize">
                                                <strong>{{\App\CentralLogics\Helpers::set_symbol( $value['optionPrice'])}}</strong></span>
                                            @endforeach
                                        @endif
                                    </td>
                                </tr>
                            @endforeach
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>

        @endif

        <div class="card">
            <div class="table-top p-3 d-flex flex-wrap gap-2 align-items-center ">
                <h5 class="mb-0">{{ translate('Product_Reviews') }}</h5>
                <span class="badge badge-soft-dark rounded-50 fz-14">{{ $reviews->total() }}</span>
            </div>
            <div class="table-responsive datatable-custom">
                <table id="datatable" class="table table-borderless table-thead-bordered table-nowrap card-table">
                    <thead class="thead-light">
                        <tr>
                            <th>{{translate('Sl')}}</th>
                            <th>{{translate('reviewer')}}</th>
                            <th>{{translate('review')}}</th>
                            <th>{{translate('date')}}</th>
                            <th>{{translate('image')}}</th>
                        </tr>
                    </thead>

                    <tbody>

                    @foreach($reviews as $key => $review)
                        <tr>
                            <td>{{ $reviews->firstitem()+$key }}</td>
                            <td>
                                <a class="d-flex align-items-center"
                                   href="{{route('admin.customer.view',[$review['user_id']])}}">
                                    <div class="avatar avatar-circle">
                                        @if($review->customer)
                                            <img class="avatar-img" width="75" height="75"
                                                 src="{{$review->customer->imageFullPath}}"
                                                 alt="">
                                        @else
                                            <img class="avatar-img" width="75" height="75"
                                                 src="{{ asset('public/assets/admin/img/160x160/img1.jpg') }}"
                                                 alt="">
                                        @endif

                                    </div>
                                    <div class="ml-3">
                                    <span class="d-block h5 text-hover-primary mb-0">
                                        @if(isset($review->customer))
                                        {{$review->customer['f_name']." ".$review->customer['l_name']}}
                                        <i class="tio-verified text-primary" data-toggle="tooltip" data-placement="top"
                                            title="Verified Customer"></i></span>
                                        <span class="d-block font-size-sm text-body">{{$review->customer->email}}</span>
                                        @else
                                            <span class="badge-pill badge-soft-dark text-muted text-sm small">
                                                {{translate('Customer unavailable')}}
                                            </span>
                                        @endif
                                    </div>
                                </a>
                            </td>
                            <td>
                                <div class="text-wrap width-18rem">
                                    <div class="d-flex mb-0">
                                        <label class="mb-0 review-color">
                                            <i class="tio-star fz-20"></i> {{$review->rating}}
                                        </label>
                                    </div>
                                    <div class="max-w300 text-wrap">
                                        <div class="d-block text-break text-dark __descripiton-txt __not-first-hidden" id="__descripiton-txt{{$review->id}}">
                                            <div>
                                                {!! $review['comment'] !!}
                                            </div>
                                            <div class="show-more text-info text-center">
                                                <span class="see-more"
                                                      id="show-more-{{$review->id}}"
                                                      data-id="{{$review->id}}"
                                                      data-more="{{ translate('See More') }}"
                                                      data-less="{{ translate('See Less') }}">
                                                    {{ translate('See More') }}
                                                </span>
                                            </div>
                                        </div>
                                    </div>

                                </div>
                            </td>
                            <td>
                                {{date('d M Y H:i:s',strtotime($review['created_at']))}}
                            </td>
                            <td>
                                <div class="w-100">
                                    <?php
                                        $images = [];
                                        $attachments = json_decode($review['attachment'], true) ?? [];

                                        foreach ($attachments as $k => $item) {
                                            if (\Illuminate\Support\Facades\Storage::disk('public')->exists('review/' . $item)) {
                                                $images[$k] = asset('storage/app/public/review/' . $item);
                                            } else {
                                                $images[$k] = asset('public/assets/admin/img/160x160/img2.jpg');
                                            }
                                        }
                                    ?>
                                    @foreach($images as $attachment)
                                        <a href="{{$attachment}}" data-lightbox >
                                            <img class="m-1 img-100" src="{{ $attachment }}" alt="Review Image" width="60">
                                        </a>
                                    @endforeach

                                </div>
                            </td>
                        </tr>
                    @endforeach
                    </tbody>
                </table>
            </div>

            <div class="card-footer">
                <div class="row justify-content-center justify-content-sm-between align-items-sm-center">
                    <div class="col-12">
                        {!! $reviews->links() !!}
                    </div>
                </div>
            </div>
        </div>

    </div>
@endsection

@push('script_2')
    <script>
        $('.see-more').on('click', function (){
            let id = $(this).data('id');
            showMore(id)
        });

        function showMore(id) {
            const textBlock = $('#__descripiton-txt' + id);
            const button = $('#show-more-' + id);

            textBlock.toggleClass('__not-first-hidden');

            if (button.hasClass('active')) {
                button.text(button.data('more')).removeClass('active');
            } else {
                button.text(button.data('less')).addClass('active');
            }
        }

        $(document).ready(function () {
            // Language switcher
            $('.lang_link').click(function (e) {
                e.preventDefault();
                $('.lang_link').removeClass('active');
                $('.lang_form').addClass('d-none');
                $(this).addClass('active');

                let form_id = this.id;
                let lang = form_id.substring(0, form_id.length - 5);
                $('#' + lang + '-div').removeClass('d-none');
            });
        });


        $(".recommended-status-change").change(function() {
            var value = $(this).val();
            let url = $(this).data('url');
            console.log(value, url);
            status_change(this, url);
        });

        function recommended_status_change(t) {
            let url = $(t).data('url');
            let checked = $(t).prop("checked");
            let status = checked === true ? 1 : 0;

            Swal.fire({
                title: 'Are you sure?',
                text: 'Want to change the recommended status',
                type: 'warning',
                showCancelButton: true,
                confirmButtonColor: '#FC6A57',
                cancelButtonColor: 'default',
                cancelButtonText: '{{translate("No")}}',
                confirmButtonText: '{{translate("Yes")}}',
                reverseButtons: true
            }).then((result) => {
                    if (result.value) {
                        $.ajaxSetup({
                            headers: {
                                'X-CSRF-TOKEN': $('meta[name="_token"]').attr('content')
                            }
                        });
                        $.ajax({
                            url: url,
                            data: {
                                status: status
                            },
                            success: function (data, status) {
                                toastr.success("{{translate('updated successfully')}}");
                            },
                            error: function (data) {
                                toastr.error("{{translate('updated failed')}}");
                            }
                        });
                    }
                    else if (result.dismiss) {
                        if (status == 1) {
                            $('#' + t.id).prop('checked', false)

                        } else if (status == 0) {
                            $('#'+ t.id).prop('checked', true)
                        }
                        toastr.info("{{translate("recommended status has not changed")}}");
                    }
                }
            )
        }

    </script>
@endpush

@push('script_2')
    <script>
        "use strict";
        var lightbox = function (o) {
            var s = void 0,
                c = void 0,
                u = void 0,
                d = void 0,
                i = void 0,
                p = void 0,
                m = document,
                e = m.body,
                l = "fadeIn .3s",
                v = "fadeOut .3s",
                t = "scaleIn .3s",
                f = "scaleOut .3s",
                a = "lightbox-btn",
                n = "lightbox-gallery",
                b = "lightbox-trigger",
                g = "lightbox-active-item",
                y = function () {
                    return e.classList.toggle("remove-scroll");
                },
                r = function (e) {
                    if (
                        ("A" === o.tagName && (e = e.getAttribute("href")),
                            e.match(/\.(jpeg|jpg|gif|png)/))
                    ) {
                        var t = m.createElement("img");
                        return (
                            (t.className = "lightbox-image"),
                                (t.src = e),
                            "A" === o.tagName &&
                            (t.alt = o.getAttribute("data-image-alt")),
                                t
                        );
                    }
                    if (e.match(/(youtube|vimeo)/)) {
                        var a = [];
                        return (
                            e.match("youtube") &&
                            ((a.id = e
                                .split(/v\/|v=|youtu\.be\//)[1]
                                .split(/[?&]/)[0]),
                                (a.url = "youtube.com/embed/"),
                                (a.options = "?autoplay=1&rel=0")),
                            e.match("vimeo") &&
                            ((a.id = e
                                .split(/video\/|https:\/\/vimeo\.com\//)[1]
                                .split(/[?&]/)[0]),
                                (a.url = "player.vimeo.com/video/"),
                                (a.options = "?autoplay=1title=0&byline=0&portrait=0")),
                                (a.player = m.createElement("iframe")),
                                a.player.setAttribute("allowfullscreen", ""),
                                (a.player.className = "lightbox-video-player"),
                                (a.player.src = "https://" + a.url + a.id + a.options),
                                (a.wrapper = m.createElement("div")),
                                (a.wrapper.className = "lightbox-video-wrapper"),
                                a.wrapper.appendChild(a.player),
                                a.wrapper
                        );
                    }
                    return m.querySelector(e).children[0].cloneNode(!0);
                },
                h = function (e) {
                    var t = {
                        next: e.parentElement.nextElementSibling,
                        previous: e.parentElement.previousElementSibling,
                    };
                    for (var a in t)
                        null !== t[a] && (t[a] = t[a].querySelector("[data-lightbox]"));
                    return t;
                },
                x = function (e) {
                    p.removeAttribute("style");
                    var t = h(u)[e];
                    if (null !== t)
                        for (var a in ((i.style.animation = v),
                            setTimeout(function () {
                                i.replaceChild(r(t), i.children[0]),
                                    (i.style.animation = l);
                            }, 200),
                            u.classList.remove(g),
                            t.classList.add(g),
                            (u = t),
                            c))
                            c.hasOwnProperty(a) && (c[a].disabled = !h(t)[a]);
                },
                E = function (e) {
                    var t = e.target,
                        a = e.keyCode,
                        i = e.type;
                    ((("click" == i && -1 !== [d, s].indexOf(t)) ||
                        ("keyup" == i && 27 == a)) &&
                    d.parentElement === o.parentElement &&
                    (N("remove"),
                        (d.style.animation = v),
                        (p.style.animation = [f, v]),
                        setTimeout(function () {
                            if ((y(), o.parentNode.removeChild(d), "A" === o.tagName)) {
                                u.classList.remove(g);
                                var e = m.querySelector("." + b);
                                e.classList.remove(b), e.focus();
                            }
                        }, 200)),
                        c) &&
                    ((("click" == i && t == c.next) || ("keyup" == i && 39 == a)) &&
                    x("next"),
                    (("click" == i && t == c.previous) ||
                        ("keyup" == i && 37 == a)) &&
                    x("previous"));
                    if ("keydown" == i && 9 == a) {
                        var l = ["[href]", "button", "input", "select", "textarea"];
                        l = l.map(function (e) {
                            return e + ":not([disabled])";
                        });
                        var n = (l = d.querySelectorAll(l.toString()))[0],
                            r = l[l.length - 1];
                        e.shiftKey
                            ? m.activeElement == n && (r.focus(), e.preventDefault())
                            : (m.activeElement == r && (n.focus(), e.preventDefault()),
                                r.addEventListener("blur", function () {
                                    r.disabled && (n.focus(), e.preventDefault());
                                }));
                    }
                },
                N = function (t) {
                    ["click", "keyup", "keydown"].forEach(function (e) {
                        "remove" !== t
                            ? m.addEventListener(e, function (e) {
                                return E(e);
                            })
                            : m.removeEventListener(e, function (e) {
                                return E(e);
                            });
                    });
                };
            !(function () {
                if (
                    ((s = m.createElement("button")).setAttribute(
                        "aria-label",
                        "Close"
                    ),
                        (s.className = a + " " + a + "-close"),
                        ((i = m.createElement("div")).className = "lightbox-content"),
                        i.appendChild(r(o)),
                        ((p = i.cloneNode(!1)).className = "lightbox-wrapper"),
                        (p.style.animation = [t, l]),
                        p.appendChild(s),
                        p.appendChild(i),
                        ((d = i.cloneNode(!1)).className = "lightbox-container"),
                        (d.style.animation = l),
                        (d.onclick = function () {}),
                        d.appendChild(p),
                    "A" === o.tagName && "gallery" === o.getAttribute("data-lightbox"))
                )
                    for (var e in (d.classList.add(n),
                        (c = { previous: "", next: "" })))
                        c.hasOwnProperty(e) &&
                        ((c[e] = s.cloneNode(!1)),
                            c[e].setAttribute("aria-label", e),
                            (c[e].className = a + " " + a + "-" + e),
                            (c[e].disabled = !h(o)[e]),
                            p.appendChild(c[e]));
                "A" === o.tagName &&
                (o.blur(), (u = o).classList.add(g), o.classList.add(b)),
                    o.parentNode.insertBefore(d, o.nextSibling),
                    y();
            })(),
                N();
        };

        Array.prototype.forEach.call(
            document.querySelectorAll("[data-lightbox]"),
            function (t) {
                t.addEventListener("click", function (e) {
                    e.preventDefault(), new lightbox(t);
                });
            }
        );

    </script>
@endpush
