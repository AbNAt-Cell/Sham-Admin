@php
    $orderProducts = session()->get("order_products_".$orderId, []);
@endphp

<div class="mb-80 order-products">
    <div class="mb-2 d-flex align-items-center gap-1">
        <h4 class="mb-0">{{ translate('Product List') }}</h4>
        <span class="badge badge-soft-dark rounded-50 fz-12">{{ count($orderProducts) }}</span>
    </div>
    <div class="table-responsive product_table border">
        <table class="table table-align-middle mb-0">
            <thead class="text-dark bg-light">
            <tr>
                <th class="border-0">{{ translate('SL') }}</th>
                <th class="text-capitalize border-0 min-w-120">{{ translate('Item_Details') }}</th>
                <th class="text-capitalize text-center border-0">{{ translate('Qty') }}</th>
                <th class="text-capitalize text-right border-0">{{ translate('Total') }}</th>
                <th class="text-capitalize text-center border-0">{{ translate('Action') }}</th>
            </tr>
            </thead>
            <tbody>
            @foreach($orderProducts as $index => $detail)
                @php
                    $variation = isset($detail['variation']) ? json_decode($detail['variation'], true) : [];
                @endphp
                <tr class="{{ $detail['is_new'] == 1 ? 'bg-danger-light' : '' }}">
                    <td>{{ $loop->iteration }}</td>
                    <td>
                        <div class="media align-items-center gap-10 w-max-content">
                            <img width="44" class="avatar-img ratio-1" src="{{ $detail['image'] ?? asset('public/assets/admin/img/160x160/img2.jpg') }}" alt="">
                            <div class="media-body">
                                <div class="fz-13 text-title line-limit-1 max-w180">{{ $detail['name'] }}</div>
                                @if(!empty($variation))
                                    <div class="d-flex gap-2 flex-wrap">
                                        @foreach($variation as $var)
                                            <span class="d-block text-capitalize">
                                                <strong>{{ $var['name'] ?? '' }} :</strong>
                                                @foreach($var['values'] ?? [] as $value)
                                                    {{ $value['label'] ?? '' }} ({{ Helpers::set_symbol($value['optionPrice'] ?? 0) }})
                                                @endforeach
                                            </span>
                                        @endforeach
                                    </div>
                                @endif
                            </div>
                        </div>
                    </td>
                    <td>
                        <div class="product-quantity d-flex align-items-center justify-content-center">
                            <div class="align-items-center border d-flex product-quantity-group rounded">
                                <button class="bg-transparent btn btn-number p-2 text-dark edit-product-quantity-btn" type="button"
                                        data-type="minus"
                                        data-order-id="{{ $orderId }}"
                                        data-product-id="{{ $detail['id'] }}"
                                        data-field="quantity"
                                        data-stock_type="unlimited"
                                        {{ $detail['quantity'] == 1 ? 'disabled' : ''}}>
                                    <i class="tio-remove font-weight-bold"></i>
                                </button>

                                <input class="form-control input-number text-center edit-product-cart-qty-field"
                                       placeholder="1"
                                       type="number"
                                       name="quantity"
                                       value="{{ $detail['quantity'] }}"
                                       data-order-id="{{ $orderId }}"
                                       data-product-id="{{ $detail['id'] }}"
                                       min="1">

                                <button class="bg-transparent btn btn-number p-2 text-dark edit-product-quantity-btn"
                                        type="button"
                                        data-type="plus"
                                        data-order-id="{{ $orderId }}"
                                        data-product-id="{{ $detail['id'] }}"
                                        data-field="quantity"
                                        data-stock_type="unlimited">
                                    <i class="tio-add font-weight-bold"></i>
                                </button>
                            </div>
                        </div>
                    </td>
                    <td class="text-right">{{ Helpers::set_symbol($detail['price'] * $detail['quantity']) }}</td>
                    <td>
                        <div class="d-flex justify-content-center">
                            <a href="javascript:void(0)" class="remove_product btn btn-danger rounded-circle square-btn"
                               data-index="{{ $index }}"
                               data-order-id="{{ $orderId }}"
                            ><i class="tio-delete-outlined"></i>
                            </a>
                        </div>
                    </td>

                </tr>
            @endforeach
            </tbody>
        </table>
    </div>
</div>
