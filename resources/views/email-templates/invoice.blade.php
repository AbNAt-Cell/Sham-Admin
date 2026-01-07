<!DOCTYPE html>
<html lang="en">

<head>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta http-equiv="Content-Type" content="text/html;"/>
    <meta charset="UTF-8">
    <title>Invoice #{{ $order->id }}</title>


    <style>
        @import url('https://fonts.googleapis.com/css2?family=Roboto:ital,wght@0,400;0,500;0,700;1,400&display=swap');

        body, * {
            font-family: 'DejaVu Sans', sans-serif !important;
        }

        @media print {
            .non-printable {
                display: none;
            }

            .printable {
                display: block;
            }
        }

        .hr {
            margin-top: 1rem;
            margin-bottom: 1rem;
            border: 0;
            border-top: .0625rem solid #e7eaf3;
            box-sizing: content-box;
            height: 0;
            overflow: visible;
        }

        .hr-style-2 {
            border: 0;
            height: 1px;
            background-image: linear-gradient(to right, rgba(0, 0, 0, 0), rgba(0, 0, 0, 0.75), rgba(0, 0, 0, 0));
        }

        .hr-style-1 {
            overflow: visible;
            padding: 0;
            border: none;
            border-top: medium double #000000;
            text-align: center;
        }

        .text-dark {
            color: #1e2022 !important
        }

        #printableAreaContent * {
            font-weight: normal !important;
        }

        #printableAreaContent {
            color: #000000;
            font-family: 'DejaVu Sans', sans-serif !important;
        }

        table tr td h5{
            padding-bottom: 100px !important;
        }

        @page {
            size: auto;
            /* auto is the initial value */
            margin: 2px;
        }
    </style>

</head>

<body>
    <div class="content container-fluid" style="color: black; max-width:40%; margin: auto;">
        <div class="row justify-content-center" id="printableArea">
            <div class="col-5" id="printableAreaContent">
                <div style="text-align: center; padding-top: 1.5rem; margin-bottom: 1rem;">
                    <h2 style="font-size: 1.3125rem; line-height: 1; font-weight: 700 !important; padding-bottom: 10px; margin: 0;">
                        {{ \App\Model\BusinessSetting::where(['key' => 'restaurant_name'])->first()->value }}</h2>
                    <h5
                        style="font-size: 20px; font-weight: 700 !important; line-height: 1; margin-top:0; padding-bottom: 10px; margin-bottom: 0.5rem;">
                        {{ \App\Model\BusinessSetting::where(['key' => 'address'])->first()->value }}
                    </h5>
                    <h5
                        style="font-size: 14px; font-weight: 700 !important; line-height: 1; margin-top:0; margin-bottom: 0.5rem;">
                        {{ translate('Phone') }} : {{ \App\Model\BusinessSetting::where(['key' => 'phone'])->first()->value }}
                    </h5>
                </div>

                <!-- <hr class="hr text-dark hr-style-1"
                    style="margin-top: 1rem;margin-bottom: 1rem;box-sizing: content-box;height: 0;overflow: visible;padding: 0;border: none;border-top: 1px solid #E9E9EA;text-align: center;"> -->

                <table style="width: 100%; margin-top: 30px; white-space: nowrap; border-top: 1px solid #E9E9EA; border-bottom: 1px solid #E9E9EA; padding-top: 14px; padding-bottom: 14px; padding-left: 30px; padding-right: 30px;">
                    <tr>
                        <td style="width: 50%; vertical-align: top;">
                            <h5
                                style="font-weight: 700 !important; font-size: .75rem; line-height: 1.4; margin-top: 0;">
                                {{ translate('Order ID : ') }}{{ $order['id'] }}
                            </h5> <br> <br>
                        </td>
                        <td style="width: 50%; vertical-align: top; text-align: right;">
                            <h5
                                style="font-weight: 700 !important; font-size: .75rem; line-height: 1.4; margin-top: 0;">
                                <span
                                    style="font-weight: normal;">{{ date('d/M/Y h:m a', strtotime($order['created_at'])) }}</span>
                            </h5> <br>
                        </td>
                    </tr>
                    <tr>
                        <td colspan="2" style="width: 100%; vertical-align: top;">
                            @if ($order->is_guest == 0)
                                @if (isset($order->customer))
                                    <h5
                                        style="font-weight: 700 !important; font-size: .75rem; line-height: 1.4;">
                                        {{ translate('Customer Name : ') }}<span
                                            style="font-weight: normal">{{ $order->customer['f_name'] . ' ' . $order->customer['l_name'] }}</span>
                                    </h5> <br>
                                    <h5
                                        style="font-weight: 700 !important; font-size: .75rem; line-height: 1.4;">
                                        {{ translate('Phone : ') }}<span
                                            style="font-weight: normal">{{ $order->customer['phone'] }}</span>
                                    </h5> <br>
                                    <h5
                                        style="font-weight: 700 !important; font-size: .75rem; line-height: 1.4;">
                                        {{ translate('Address : ') }}<span
                                            style="font-weight: normal">{{ isset($order->address) ? $order->address['address'] : '' }}</span>
                                    </h5>
                                @endif
                            @endif
                            @if ($order->is_guest == 1)
                                @if (isset($order->address))
                                    <h5
                                        style="font-weight: 700 !important; font-size: .75rem; line-height: 1.4;">
                                        {{ translate('Customer Name : ') }}<span
                                            style="font-weight: normal">{{ isset($order->address) ? $order->address['contact_person_name'] : '' }}</span>
                                    </h5>
                                    <h5
                                        style="font-weight: 700 !important; font-size: .75rem; line-height: 1.4;">
                                        {{ translate('Phone : ') }}<span
                                            style="font-weight: normal">{{ isset($order->address) ? $order->address['contact_person_number'] : '' }}</span>
                                    </h5>
                                    <h5
                                        style="font-weight: 700 !important; font-size: .75rem; line-height: 1.4;">
                                        {{ translate('Address : ') }}<span
                                            style="font-weight: normal">{{ isset($order->address) ? $order->address['address'] : '' }}</span>
                                    </h5>
                                @endif
                            @endif
                        </td>
                    </tr>
                </table>

                <!-- <h5 class="text-uppercase"
                    style="font-weight: 700 !important; font-size: .875rem; line-height: 1.4; margin-top: 0; margin-bottom: .5rem;">
                </h5> -->
                <!-- <hr class="hr text-dark hr-style-2"
                    style="margin-top: 1rem;margin-bottom: 1rem;border: 0;border-top: .0625rem solid #e7eaf3;box-sizing: content-box;overflow: visible; height: 1px; background-image: linear-gradient(to right, rgba(0, 0, 0, 0), rgba(0, 0, 0, 0.75), rgba(0, 0, 0, 0));"> -->
                <table class="table table-bordered"
                    style="border-collapse: collapse; width: 100%; margin-top: 1px; margin-bottom: 1rem;">
                    <thead>
                        <tr style="font-size: .875rem; line-height: 1.6;">
                            <th
                                style="width: 10%; padding: .75rem 20px; font-size: .75rem; text-transform: uppercase; vertical-align: bottom;">
                                {{ translate('QTY') }}</th>
                            <th
                                style="padding: .75rem; font-size: .75rem; text-transform: uppercase; vertical-align: bottom;">
                                {{ translate('DESC') }}</th>
                            <th
                                style="text-align:right; padding: .75rem; padding-right: 22px; font-size: .75rem; text-transform: uppercase; vertical-align: bottom;">
                                {{ translate('Price') }}</th>
                        </tr>
                    </thead>


                    <tbody>
                        @php($subTotal = 0)
                        @php($totalTax = 0)
                        @php($totalDisOnPro = 0)
                        @php($addOnsCost = 0)
                        @php($addOnTax = 0)
                        @php($add_ons_tax_cost = 0)
                        @foreach ($order->details as $detail)
                            @if ($detail->product)
                                @php($addOnQtys = json_decode($detail['add_on_qtys'], true))
                                @php($addOnPrices = json_decode($detail['add_on_prices'], true))
                                @php($addOnTaxes = json_decode($detail['add_on_taxes'], true))

                                <tr style="font-size: .875rem; line-height: 1.6;">
                                    <td
                                        style="border: .0625rem solid rgba(231, 234, 243, .7); padding: 22px; vertical-align: top;">
                                        {{ $detail['quantity'] }}
                                    </td>
                                    <td
                                        style="border: .0625rem solid rgba(231, 234, 243, .7); padding: 22px; vertical-align: top;">
                                        <span style="word-break: break-all;">
                                            {{ Str::limit($detail->product['name'], 200) }}</span><br> <br>
                                        @if (count(json_decode($detail['variation'], true)) > 0)
                                            <strong style="font-weight: 500;"><u>{{ translate('variation') }} : </u></strong>
                                            <br>
                                            @foreach (json_decode($detail['variation'], true) as $variation)
                                                @if (isset($variation['name']) && isset($variation['values']))
                                                    <span style="display: block; text-transform: capitalize;">
                                                        <strong style="font-weight: 500;">{{ $variation['name'] }} - </strong> <br> <br>
                                                    </span>
                                                    @foreach ($variation['values'] as $value)
                                                        <span style="display: block; text-transform: capitalize;">
                                                            {{ $value['label'] }} :
                                                            <span>{{ \App\CentralLogics\Helpers::set_symbol($value['optionPrice']) }}</span>
                                                        </span> <br> <br>
                                                    @endforeach

                                                @else
                                                    @if (isset(json_decode($detail['variation'], true)[0]))
                                                        @foreach (json_decode($detail['variation'], true)[0] as $key1 => $variation)
                                                            <div class="font-size-sm text-body"
                                                                style="font-size: .8125rem; color: #677788 !important;">
                                                                <span>{{ $key1 }} : </span>
                                                                <span
                                                                    style="font-weight: bold;">{{ $variation }}</span>
                                                            </div>
                                                        @endforeach
                                                    @endif
                                                @break
                                            @endif
                                        @endforeach
                                    @else
                                        <div class="font-size-sm text-body"
                                            style="font-size: .8125rem; color: #677788 !important;">
                                            <span>{{ translate('Price') }} : </span>
                                            <span
                                                style="font-weight: bold;">{{ \App\CentralLogics\Helpers::set_symbol($detail->price) }}</span>
                                        </div>
                                    @endif



                                    @foreach (json_decode($detail['add_on_ids'], true) as $key2 => $id)
                                        @php($addon = \App\Model\AddOn::find($id))
                                        @if ($key2 == 0)
                                            <strong><u >{{ translate('Addons : ') }}</u></strong> <br> <br>
                                        @endif

                                        @if ($addOnQtys == null)
                                            @php($add_on_qty = 1)
                                        @else
                                            @php($add_on_qty = $addOnQtys[$key2])
                                        @endif

                                        <div class="font-size-sm text-body"
                                            style="font-size: .8125rem; color: #677788 !important;">
                                            <span>{{ $addon ? $addon['name'] : translate('addon deleted') }} :
                                            </span>
                                            <span class="font-weight-bold">
                                                {{ $add_on_qty }} x
                                                {{ \App\CentralLogics\Helpers::set_symbol($addOnPrices[$key2]) }}
                                            </span>
                                        </div> <br>
                                        @php($addOnsCost += $addOnPrices[$key2] * $add_on_qty)
                                        @php($add_ons_tax_cost += $addOnTaxes[$key2] * $add_on_qty)
                                    @endforeach

                                    {{ translate('Discount : ') }}{{ \App\CentralLogics\Helpers::set_symbol($detail['discount_on_product']) }}
                                </td>
                                <td
                                    style="border: .0625rem solid rgba(231, 234, 243, .7); padding: .75rem; vertical-align: top; width: 28%;padding-right: 22px; text-align:right;">
                                    @php($amount = ($detail['price'] - $detail['discount_on_product']) * $detail['quantity'])
                                    {{ \App\CentralLogics\Helpers::set_symbol($amount) }}
                                </td>
                            </tr>
                            @php($subTotal += $amount)
                            @php($totalTax += $detail['tax_amount'] * $detail['quantity'])
                        @endif
                    @endforeach
                </tbody>
            </table>

            <table role="presentation" width="100%" cellspacing="0" cellpadding="5" border="0"
                style="color: black!important; text-align: right; font-size: .875rem; line-height: 1.6; padding: 0px 22px; width: 400px; margin-left: auto;">
                <tr>
                    <td width="50%" style="text-align: left !important;"><strong>{{ translate('Items Price:') }}</strong></td>
                    <td width="50%">{{ \App\CentralLogics\Helpers::set_symbol($subTotal) }}</td>
                </tr>

                <tr>
                    <td style="text-align: left !important;"><strong>{{ translate('Addon Cost:') }}</strong></td>
                    <td>{{ \App\CentralLogics\Helpers::set_symbol($addOnsCost) }}</td>
                </tr>
                <tr>
                    <td style="text-align: left !important;"><strong>{{ translate('Coupon Discount:') }}</strong></td>
                    <td>- {{ \App\CentralLogics\Helpers::set_symbol($order['coupon_discount_amount']) }}</td>
                </tr>
                <tr>
                    <td style="text-align: left !important;"><strong>{{ translate('Extra Discount:') }}</strong></td>
                    <td>- {{ \App\CentralLogics\Helpers::set_symbol($order['extra_discount']) }}</td>
                </tr>

                <tr>
                    <td style="text-align: left !important;"><strong>{{ translate('Tax / VAT:') }}</strong></td>
                    <td>{{ \App\CentralLogics\Helpers::set_symbol($totalTax + $add_ons_tax_cost) }}</td>
                </tr>
                <tr>
                    <td style="text-align: left !important;"><strong>{{ translate('Delivery Fee:') }}</strong></td>
                    <td>
                        @if ($order['order_type'] == 'take_away')
                            @php($del_c = 0)
                        @else
                            @php($del_c = $order['delivery_charge'])
                        @endif
                        {{ \App\CentralLogics\Helpers::set_symbol($del_c) }}
                    </td>
                </tr>
                <tr>
                    <td colspan="2">

                    </td>
                </tr>
                <tr>
                    <td style="font-size: 20px; text-align: left !important;"><strong>{{ translate('Total:') }}</strong></td>
                    <td style="font-size: 20px;">
                        {{ \App\CentralLogics\Helpers::set_symbol($subTotal + $del_c + $totalTax + $addOnsCost - $order['coupon_discount_amount'] - $order['extra_discount'] + $add_ons_tax_cost) }}
                    </td>
                </tr>

                <!-- Partial Payment -->
                @if ($order->order_partial_payments->isNotEmpty())
                    @foreach ($order->order_partial_payments as $partial)
                        <tr>
                            <td><strong>{{ translate('Paid By') }}
                                    ({{ str_replace('_', ' ', $partial->paid_with) }})
                                    :</strong></td>
                            <td>{{ \App\CentralLogics\Helpers::set_symbol($partial->paid_amount) }}</td>
                        </tr>
                    @endforeach
                    <?php
                    $due_amount = $order->order_partial_payments->first()?->due_amount ?? 0;
                    ?>
                    <tr>
                        <td><strong>{{ translate('Due Amount:') }}</strong></td>
                        <td>{{ \App\CentralLogics\Helpers::set_symbol($due_amount) }}</td>
                    </tr>
                @endif

                @if ($order->order_change_amount()->exists())
                    <tr>
                        <td><strong>{{ translate('Paid Amount:') }}</strong></td>
                        <td>{{ \App\CentralLogics\Helpers::set_symbol($order->order_change_amount?->paid_amount) }}
                        </td>
                    </tr>
                    @php($changeOrDueAmount = $order->order_change_amount?->paid_amount - $order->order_change_amount?->order_amount)
                    <tr>
                        <td><strong>{{ $changeOrDueAmount < 0 ? translate('Due Amount') : translate('Change Amount') }}:</strong>
                        </td>
                        <td>{{ \App\CentralLogics\Helpers::set_symbol($changeOrDueAmount) }}</td>
                    </tr>
                @endif
            </table>

            <!-- <hr class="hr text-dark hr-style-2"
                style="margin-top: 1rem;margin-bottom: 1rem;border: 0;border-top: .0625rem solid #e7eaf3;box-sizing: content-box;overflow: visible; height: 1px; background-image: linear-gradient(to right, rgba(0, 0, 0, 0), rgba(0, 0, 0, 0.75), rgba(0, 0, 0, 0));"> -->
            <h5 class="text-center"
                style="font-size: .875rem; line-height: 1.4; text-align: center; margin-top: 50px;">
                {{ translate('"""THANK YOU"""') }}
            </h5>
            <!-- <hr class="hr text-dark hr-style-2"
                style="margin-top: 1rem;margin-bottom: 1rem;border: 0;border-top: .0625rem solid #e7eaf3;box-sizing: content-box;overflow: visible; height: 1px; background-image: linear-gradient(to right, rgba(0, 0, 0, 0), rgba(0, 0, 0, 0.75), rgba(0, 0, 0, 0));"> -->
            <div class="" style="border-top: 1px solid #E9E9EA; border-bottom: 1px solid #E9E9EA; padding: 14px 22px; ">
                <div class="text-center" style="font-size: .875rem; line-height: 1.6; text-align: center;">
                    {{ \App\Model\BusinessSetting::where(['key' => 'footer_text'])->first()->value }}</div>
            </div>
        </div>
    </div>
</div>

</body>

</html>
