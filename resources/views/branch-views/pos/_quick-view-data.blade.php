<div class="modal-header p-2">
    <h4 class="modal-title product-title"></h4>
    <button class="close call-when-done" type="button" data-dismiss="modal" aria-label="Close">
        <span aria-hidden="true">&times;</span>
    </button>
</div>
<form id="add-to-cart-form">
    @csrf
    <div class="modal-body pt-0">
        <div class="d-flex flex-wrap gap-3">
            <div class="d-flex align-items-center justify-content-center active">
                <img class="img-responsive rounded ratio-1 object-cover" width="160"
                    src="{{$product['imageFullPath']}}"
                    data-zoom="{{$product['imageFullPath']}}"
                    alt="Product image" width="">
                <div class="cz-image-zoom-pane"></div>
            </div>

            <?php
                $pb = json_decode($product->product_by_branch, true);

                $price = 0;
                $discountData = [];

                if(isset($pb[0])){
                    $price = $pb[0]['price'];
                    $discountData =[
                        'discount_type' => $pb[0]['discount_type'],
                        'discount' => $pb[0]['discount']
                    ];
                }

                $stockType = 'unlimited';
                $availableStock = 0;
                if($pb[0]['stock_type'] == 'daily' || $pb[0]['stock_type'] == 'fixed'){
                    $availableStock = $pb[0]['stock'] - $pb[0]['sold_quantity'];
                    $stockType = 'limited';
                }
            ?>

            <div class="details">
                <div class="break-all">
                    <a href="#" class="d-block h3 mb-2 product-title product-title">{{ Str::limit($product->name, 100) }}</a>
                </div>

                <div class="mb-2 text-dark d-flex align-items-center gap-2">
                    @if($discountData['discount'] > 0)
                        <strike class="fz-12">
                            {{Helpers::set_symbol($price) }}
                        </strike>
                    @endif
                    <h4 class="text-accent mb-0">
                        {{Helpers::set_symbol(($price - Helpers::discount_calculate($discountData, $price))) }}
                    </h4>
                    @if($discountData['discount'] > 0)
                        <span class="badge badge-danger p-1 fz-13">
                            - {{ $discountData['discount_type'] == 'percent' ? $discountData['discount']. '%' :  Helpers::set_symbol($discountData['discount']) }}
                        </span>
                    @endif
                </div>
                <div class="mb-3 text-title d-flex align-items-center gap-3 border px-3 py-2 rounded fz-12">
                    <span>{{ translate('ID') }} #{{ $product->id }}</span>
                    @if($pb[0]['stock_type'] == 'unlimited')
                        <span class="dot-before"><i class="tio-cube mr-1"></i>{{ translate('unlimited') }}</span>
                    @else
                        <span class="dot-before"><i class="tio-cube mr-1"></i>{{ translate('only') }} {{ $pb[0]['stock'] - $pb[0]['sold_quantity'] }} {{ translate('left') }}</span>
                    @endif
                </div>
                <div>
                    <span class="badge badge-soft-secondary fz-12 px-3 py-2 text-title">
                        <img width="13" class="mr-1" src="{{asset('public/assets/admin/img/icons/leaf.svg')}}" alt="{{ translate('veg tag') }}">
                        {{ translate($product->product_type) }}
                    </span>
                    @php($halalTagStatus = (integer) (\App\CentralLogics\Helpers::get_business_settings('halal_tag_status') ?? 0))
                    @if($halalTagStatus && $pb[0]['halal_status'] )
                        <span class="badge badge-soft-secondary fz-12 px-3 py-2 text-title">
                        <img width="13" class="mr-1" src="{{asset('public/assets/admin/img/halal-tags.png')}}" alt="{{ translate('halal tag') }}">
                        {{ translate("Halal") }}
                    </span>
                    @endif
                </div>
            </div>
        </div>
        <div class="row pt-2">
            <div class="col-12">
                <?php
                $cart = false;
                if (session()->has('cart')) {
                    foreach (session()->get('cart') as $key => $cartItem) {
                        if (is_array($cartItem) && $cartItem['id'] == $product['id']) {
                            $cart = $cartItem;
                        }
                    }
                }

                ?>
                @if($product->description)
                    <h3 class="mt-3">{{translate('description')}}</h3>
                    <div class="d-block text-break text-dark __descripiton-txt __not-first-hidden min-h-auto">
                        <div>
                            <p>
                                {!! $product->description !!}
                            </p>
                        </div>
                        <div class="show-more text-info text-center">
                            <span class="">See More</span>
                        </div>
                    </div>
                @endif

                    <div class="d-flex flex-column gap-3">
                        <input type="hidden" name="id" value="{{ $product->id }}">
                        @if (isset($product->product_by_branch) && count($product->product_by_branch))
                            @foreach($product->product_by_branch as $branch_product)
                                @foreach ($branch_product->variations as $key => $choice)
                                    @if (isset($choice->price) == false)
                                    <div class="border rounded p-3 variation-group">
                                        <div class="h3 p-0 d-flex justify-content-between align-items-center">
                                            <span>{{ $choice['name'] }}</span>
                                            <span class="badge badge-soft-secondary font-weight-medium variant-name-optional-or-required-label">{{ ($choice['required'] == 'on')  ?  translate('Required') : translate('optional') }}</span>
                                        </div>
                                        @if ($choice['min'] != 0 && $choice['max'] != 0)
                                            <small class="d-block mb-3">
                                                {{ translate('You_need_to_select_minimum_ ') }} {{ $choice['min'] }} {{ translate('to_maximum_ ') }} {{ $choice['max'] }} {{ translate('options') }}
                                            </small>
                                        @endif

                                        <div class="d-flex flex-column gap-2 mt-3">
                                            <input type="hidden"  name="variations[{{ $key }}][min]" value="{{ $choice['min'] }}" >
                                            <input type="hidden"  name="variations[{{ $key }}][max]" value="{{ $choice['max'] }}" >
                                            <input type="hidden"  name="variations[{{ $key }}][required]" value="{{ $choice['required'] }}" >
                                            <input type="hidden" name="variations[{{ $key }}][name]" value="{{ $choice['name'] }}">
                                            @foreach ($choice['values'] as $k => $option)
                                                <div class="d-flex form--check form-check user-select-none">
                                                    <div class="d-flex gap-2">
                                                        <input class="form-check-input variation-input" type="{{ ($choice['type'] == "multi") ? "checkbox" : "radio"}}" id="choice-option-{{ $key }}-{{ $k }}"
                                                        name="variations[{{ $key }}][values][label][]" value="{{ $option['label'] }}" autocomplete="off">

                                                    <label class="form-check-label"
                                                        for="choice-option-{{ $key }}-{{ $k }}">{{ Str::limit($option['label'], 20, '...') }}</label>
                                                    </div>
                                                    <span class="ml-auto">{{ \App\CentralLogics\Helpers::set_symbol($option['optionPrice']) }}</span>
                                                </div>
                                            @endforeach
                                        </div>
                                    </div>
                                    @endif
                                @endforeach
                            @endforeach
                        @else
                            @foreach (json_decode($product->variations) as $key => $choice)

                                @if (isset($choice->price) == false)
                                    <div class="h3 p-0 pt-2">
                                        {{ $choice->name }}
                                        <small class="text-muted custom-text-size12">
                                            ({{ ($choice->required == 'on')  ?  translate('Required') : translate('optional') }})
                                        </small>
                                    </div>
                                    @if ($choice->min != 0 && $choice->max != 0)
                                        <small class="d-block mb-3">
                                            {{ translate('You_need_to_select_minimum_ ') }} {{ $choice->min }} {{ translate('to_maximum_ ') }} {{ $choice->max }} {{ translate('options') }}
                                        </small>
                                    @endif

                                    <div>
                                        <input type="hidden"  name="variations[{{ $key }}][min]" value="{{ $choice->min }}" >
                                        <input type="hidden"  name="variations[{{ $key }}][max]" value="{{ $choice->max }}" >
                                        <input type="hidden"  name="variations[{{ $key }}][required]" value="{{ $choice->required }}" >
                                        <input type="hidden" name="variations[{{ $key }}][name]" value="{{ $choice->name }}">
                                        @foreach ($choice->values as $k => $option)
                                            <div class="form-check form--check d-flex pr-5 mr-6">
                                                <input class="form-check-input" type="{{ ($choice->type == "multi") ? "checkbox" : "radio"}}" id="choice-option-{{ $key }}-{{ $k }}"
                                                    name="variations[{{ $key }}][values][label][]" value="{{ $option->label }}" autocomplete="off">

                                                <label class="form-check-label"
                                                    for="choice-option-{{ $key }}-{{ $k }}">{{ Str::limit($option->label, 20, '...') }}</label>
                                                <span class="ml-auto">{{ \App\CentralLogics\Helpers::set_symbol($option->optionPrice) }}</span>
                                            </div>
                                        @endforeach
                                    </div>

                                @endif
                            @endforeach
                        @endif

                        @php($add_ons = json_decode($product->add_ons))
                        @if(count($add_ons)>0)
                           <div class="p-3 shadow rounded-10">
                            <h3>{{ translate('addon') }}</h3>
                            <div class="d-flex flex-column gap-2 addon-wrap">
                                @foreach (\App\Model\AddOn::whereIn('id', $add_ons)->get() as $key => $add_on)
                                    <div class="addon-item d-flex gap-3 justify-content-between align-items-center">
                                        <input type="hidden" name="addon-price{{ $add_on->id }}" value="{{$add_on->price}}">
                                        <div class="d-flex align-items-center gap-2">
                                            <input class="addon-chek" type="checkbox"
                                            id="addon{{ $key }}" onchange="addon_quantity_input_toggle(event)"
                                            name="addon_id[]" value="{{ $add_on->id }}"
                                            autocomplete="off">
                                            <label class="user-select-none mb-0 text-black-50 fw-medium addon_label"
                                                for="addon{{ $key }}">{{ $add_on->name }}
                                            </label>
                                        </div>
                                    <div class="d-flex align-items-baseline gap-3 flex-wrap">
                                            <span class="user-select-none mb-0 text-black-50 fw-medium fz-12 addon_label"
                                                for="addon{{ $key }}">
                                                {{ \App\CentralLogics\Helpers::set_symbol($add_on->price) }}
                                            </span>
                                            <label class="input-group addon-quantity-input addon-quantity-input_custom shadow bg-white rounded mb-0 d-none align-items-center w-auto fz-12"
                                                for="addon{{ $key }}">
                                                <button class="btn btn-sm h-100 text-dark pl-1 py-1 pr-0" type="button"
                                                        onclick="this.parentNode.querySelector('input[type=number]').stepDown(), getVariantPrice()">
                                                    <i class="tio-remove  font-weight-bold"></i></button>
                                                <input type="number" name="addon-quantity{{ $add_on->id }}"
                                                    class="text-center border-0 h-100"
                                                    placeholder="1" value="1" min="1" max="100" readonly>
                                                <button class="btn btn-sm h-100 text-dark pr-1 py-1 pl-0" type="button"
                                                        onclick="this.parentNode.querySelector('input[type=number]').stepUp(), getVariantPrice()">
                                                    <i class="tio-add  font-weight-bold"></i></button>
                                            </label>
                                    </div>
                                    </div>
                                @endforeach
                            </div>
                           </div>
                        @endif
                    </div>
            </div>
        </div>
    </div>
    <div class="modal-footer shadow-lg bg-white border-0 d-block">
        <div class="d-flex align-items-center justify-content-between" id="chosen_price_div">
            <div class="product-description-label font-weight-bold text-dark fz-16">{{translate('Total_Price')}}</div>
            <div class="product-price font-weight-bold text-dark fz-20"><strong id="chosen_price"></strong></div>
        </div>

        <div class="d-flex align-items-center justify-content-between mt-3">
            <div class="product-quantity d-flex align-items-center">
                <div class="product-quantity-group d-flex align-items-center border-0">
                    <button class="btn btn-number text-dark p-2" type="button" data-type="minus" data-field="quantity" data-stock_type="{{$stockType}}">
                        <i class="tio-remove font-weight-bold"></i>
                    </button>

                    <input type="text" name="quantity"
                           class="form-control input-number text-center cart-qty-field"
                           placeholder="1"
                           value="1"
                           min="1"
                           @if($stockType === 'limited') max="{{ $availableStock }}" @endif>

                    <button class="btn btn-number text-dark p-2" type="button" data-type="plus" data-field="quantity" data-stock_type="{{$stockType}}">
                        <i class="tio-add font-weight-bold"></i>
                    </button>
                </div>
            </div>
            <button class="btn btn-primary px-md-5 add-to-cart-button" type="button">
                <i class="tio-shopping-cart"></i>
                {{translate('Add To Cart')}}
            </button>
        </div>
    </div>
</form>

<script>
    "use strict";

    cartQuantityInitialize();
    getVariantPrice();

    $('#add-to-cart-form input').on('change', function () {
        getVariantPrice();
    });

    $('#add-to-cart-form .variation-input').on('change', function () {
        // Find the closest variation group and its label
        var variationGroup = $(this).closest('.variation-group');
        var label = variationGroup.find('.variant-name-optional-or-required-label');
        var isRequired = variationGroup.find('input[name$="[required]"]').val() === 'on';
        var minRequired = parseInt(variationGroup.find('input[name$="[min]"]').val()) || 0;

        // Check if this is a checkbox variation
        if ($(this).attr('type') === 'checkbox') {
            // Count how many checkboxes are checked in this variation group
            var checkedCount = variationGroup.find('input[type="checkbox"]:checked').length;

            if (checkedCount >= minRequired && minRequired !== 0) {
                // Minimum requirement met
                label.html('{{ translate("Complete") }}')
                    .removeClass('badge-soft-secondary badge-soft-danger')
                    .addClass('badge-soft-success');
            } else {
                // Revert to original state
                label.html(isRequired ? '{{ translate("Required") }}' : '{{ translate("Optional") }}')
                    .removeClass('badge-soft-success')
                    .addClass(isRequired ? 'badge-soft-danger' : 'badge-soft-secondary');
            }
        } else {
            // For radio inputs
            if ($(this).is(':checked')) {
                label.html('{{ translate("Complete") }}')
                    .removeClass('badge-soft-secondary badge-soft-danger')
                    .addClass('badge-soft-success');
            }
        }
    });

    // $('.addon-chek').change(function() {
    //     addon_quantity_input_toggle($(this));
    // });

    function addon_quantity_input_toggle(event) {
        let checkbox = $(event.target);
        let quantityBox = checkbox.closest('.addon-item').find('.addon-quantity-input');
        let addonLabel = checkbox.closest('.addon-item').find('.addon_label');

        if (checkbox.is(':checked')) {
            quantityBox.removeClass('d-none').addClass('d-flex');
            addonLabel.css({
                'color': 'var(--tc) !important',
                'font-weight': '600 !important'
            });
        } else {
            quantityBox.removeClass('d-flex').addClass('d-none');
            addonLabel.css({
                'color': '',
                'font-weight': ''
            });
        }
    }


    $(document).on('change', '.addon-chek', function(event) {
        addon_quantity_input_toggle(event);
    });


    $('.decrease-quantity').click(function() {
        var input = $(this).closest('.addon-quantity-input').find('.addon-quantity');
        input.val(parseInt(input.val()) - 1);
        getVariantPrice();
    });

    $('.increase-quantity').click(function() {
        var input = $(this).closest('.addon-quantity-input').find('.addon-quantity');
        input.val(parseInt(input.val()) + 1);
        getVariantPrice();
    });

    $('.add-to-cart-button').click(function() {
        addToCart();
    });

    $('.show-more span').on('click', function(){
        $('.__descripiton-txt').toggleClass('__not-first-hidden')
        if($(this).hasClass('active')) {
            $('.show-more span').text('{{translate('See More')}}')
            $(this).removeClass('active')
        }else {
            $('.show-more span').text('{{translate('See Less')}}')
            $(this).addClass('active')
        }
    })
</script>
