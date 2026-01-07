<?php

namespace App\Http\Controllers\Api\V1;

use App\CentralLogics\Helpers;
use App\Http\Controllers\Controller;
use App\Library\Payer;
use App\Library\Payment as PaymentInfo;
use App\Library\Receiver;
use App\Model\CustomerAddress;
use App\Traits\CalculateOrderDataTrait;
use App\Traits\Payment;
use App\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Validator;
use Illuminate\Validation\ValidationException;
use function App\CentralLogics\translate;

class DigitalPaymentController extends Controller
{
    use CalculateOrderDataTrait;
    public function __construct(){
        if (is_dir('App\Traits') && trait_exists('App\Traits\Payment')) {
            $this->extendWithPaymentGatewayTrait();
        }
    }

    private function extendWithPaymentGatewayTrait()
    {
        $extendedControllerClass = $this->generateExtendedControllerClass();
        eval($extendedControllerClass);
    }

    private function generateExtendedControllerClass()
    {
        $baseControllerClass = get_class($this);
        $traitClassName = 'App\Traits\Payment';

        $extendedControllerClass = "
            class ExtendedController extends $baseControllerClass {
                use $traitClassName;
            }
        ";

        return $extendedControllerClass;
    }

    public function addFund(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'amount' => 'required|numeric|min:1',
            'payment_method' => 'required|string',
            'payment_platform' => 'required|string|in:web,app',
            'call_back' => 'required|url',
            'customer_id' => 'required|exists:users,id',
        ]);

        if ($validator->fails()) {
            return response()->json(['errors' => Helpers::error_processor($validator)], 403);
        }

        $add_fund_to_wallet = Helpers::get_business_settings('add_fund_to_wallet');
        if ($add_fund_to_wallet == 0){
            return response()->json(['errors' => ['message' => 'Add fund to wallet is not active']], 403);
        }

        $customer_id = $request->input('customer_id');
        $customer = User::firstWhere(['id' => $customer_id, 'is_active' => 1]);

        if (!isset($customer)) {
            return response()->json(['errors' => ['message' => 'Customer not found']], 403);
        }

        $payer = new Payer($customer['f_name'].' '.$customer['l_name'], $customer['email'], $customer['phone'], '');

        $additional_data = [
            'business_name' => Helpers::get_business_settings('restaurant_name') ?? '',
            'business_logo' => asset('storage/app/public/restaurant/' . Helpers::get_business_settings('logo'))
        ];

        $payment_info = new PaymentInfo(
            success_hook: 'add_fund_success',
            failure_hook: 'add_fund_fail',
            currency_code: Helpers::currency_code(),
            payment_method: $request->payment_method,
            payment_platform: $request->payment_platform,
            payer_id: $customer->id,
            receiver_id: null,
            additional_data: $additional_data,
            payment_amount: $request->amount,
            external_redirect_link: $request->call_back,
            attribute: 'add-fund',
            attribute_id: time()
        );

        $receiver_info = new Receiver('receiver_name','example.png');
        $redirect_link = Payment::generate_link($payer, $payment_info, $receiver_info);
        return response()->json(['redirect_link' => $redirect_link], 200);

    }

    public function payment(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'payment_method' => 'required',
            'call_back' => 'required',
            'payment_platform' => 'required|string|in:web,app',
            'is_partial' => 'required|in:0,1',
        ]);

        if ($validator->fails()) {
            return response()->json(['errors' => Helpers::error_processor($validator)], 403);
        }
        $customer_id = auth('api')->user()->id ?? $request->guest_id;
        $is_guest = auth('api')->user() ? 0: 1;

        $deliveryChargeInfo = [
            'branch_id' => $request['branch_id'],
            'distance' => $request['distance'],
            'selected_delivery_area' => $request['selected_delivery_area'],
            'order_type' => $request['order_type'],
        ];

        try {

            $amountData = $this->calculateOrderAmount(
                cart: $request['cart'],
                userId : $customer_id,
                isGuest : $is_guest,
                deliveryChargeInfo: $deliveryChargeInfo,
                couponCode: $request['coupon_code'] ?? null,
            );

        }  catch (ValidationException $e) {
            return response()->json(['errors' => $e->errors()], 403);
        } catch (\Exception $e) {
            DB::rollBack();
            return response()->json(['errors' => [['message' => $e->getMessage()]]], 403);
        }


        $order_amount = $amountData['order_amount'] + $amountData['delivery_charge_amount'];

        //partial payment validation
        if ($request['is_partial'] == 1){
            if ($is_guest == 1){
                return response()->json(['errors' => [['code' => 'payment_method', 'message' => translate('partial order does not applicable for guest user')]]], 403);
            }

            $customer = User::firstWhere(['id' => $customer_id, 'is_active' => 1]);

            if (Helpers::get_business_settings('wallet_status') != 1){
                return response()->json(['errors' => [['code' => 'payment_method', 'message' => translate('customer_wallet_status_is_disable')]]], 403);
            }
            if (isset($customer) && $customer->wallet_balance < 1){
                return response()->json(['errors' => [['code' => 'payment_method', 'message' => translate('since your wallet balance is less than 1, you can not place partial order')]]], 403);
            }
            $order_amount -= $customer->wallet_balance;
        }

        $additional_data = [
            'business_name' => Helpers::get_business_settings('restaurant_name') ?? '',
            'business_logo' => asset('storage/app/public/restaurant/' . Helpers::get_business_settings('logo'))
        ];


        //order place
        if ($is_guest == 1) {//guest order
            $address = CustomerAddress::where(['user_id' => $customer_id, 'is_guest' => 1])->first();
            if ($address){
                $customer = collect([
                    'f_name' => $address['contact_person_name'] ?? '',
                    'l_name' => '',
                    'phone' => $address['contact_person_number'] ?? '',
                    'email' => '',
                ]);
            }else{
                $customer = collect([
                    'f_name' => 'example',
                    'l_name' => 'customer',
                    'phone' => '+88011223344',
                    'email' => 'example@customer.com',
                ]);
            }
        } else { //normal order
            $customer = User::firstWhere(['id' => $customer_id, 'is_active' => 1]);
            if (!isset($customer)) {
                return response()->json(['errors' => ['message' => 'Customer not found']], 403);
            }
            $customer = collect([
                'f_name' => $customer['f_name'],
                'l_name' => $customer['l_name'],
                'phone' => $customer['phone'],
                'email' => $customer['email'],
            ]);
        }

        $payer = new Payer($customer['f_name'] . ' ' . $customer['l_name'] , $customer['email'], $customer['phone'], '');

        $payment_info = new PaymentInfo(
            success_hook: 'order_place',
            failure_hook: 'order_cancel',
            currency_code: Helpers::currency_code(),
            payment_method: $request->payment_method,
            payment_platform: $request->payment_platform,
            payer_id: session('customer_id'),
            receiver_id: '100',
            additional_data: $additional_data,
            payment_amount: $order_amount,
            external_redirect_link: $request->call_back,
            attribute: 'order',
            attribute_id: time()
        );

        $receiver_info = new Receiver('receiver_name','example.png');

        $redirect_link = Payment::generate_link($payer, $payment_info, $receiver_info);

        return response()->json(['redirect_link' => $redirect_link], 200);
    }

}
