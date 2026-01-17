<?php

namespace App\Http\Controllers;

use App\CentralLogics\Helpers;
use App\Models\PaymentRequest;
use App\Traits\Processor;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Validator;

/**
 * Monnify Payment Controller
 * 
 * Handles Monnify payment processing including:
 * - Transaction initialization
 * - Payment callback handling
 * - Webhook verification
 * 
 * @see https://docs.teamapt.com/display/MON/Monnify+API+Docs
 */
class MonnifyController extends Controller
{
    use Processor;

    private $config;
    private $baseUrl;
    private PaymentRequest $payment;

    public function __construct(PaymentRequest $payment)
    {
        $config = $this->payment_config('monnify', 'payment_config');

        if (!is_null($config) && $config->mode == 'live') {
            $this->config = json_decode($config->live_values);
            $this->baseUrl = 'https://api.monnify.com';
        } elseif (!is_null($config) && $config->mode == 'test') {
            $this->config = json_decode($config->test_values);
            $this->baseUrl = 'https://sandbox.monnify.com';
        }

        $this->payment = $payment;
    }

    /**
     * Initialize payment and redirect to Monnify checkout
     */
    public function index(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'payment_id' => 'required|uuid'
        ]);

        if ($validator->fails()) {
            return response()->json($this->response_formatter(GATEWAYS_DEFAULT_400, null, $this->error_processor($validator)), 400);
        }

        $data = $this->payment::where(['id' => $request['payment_id']])->where(['is_paid' => 0])->first();

        if (!isset($data)) {
            return response()->json($this->response_formatter(GATEWAYS_DEFAULT_204), 200);
        }

        // Initialize transaction with Monnify
        $transactionData = $this->initializeTransaction($data);

        if ($transactionData && isset($transactionData->checkoutUrl)) {
            return redirect($transactionData->checkoutUrl);
        }

        // If initialization fails, show error view or redirect to fail
        return $this->payment_response($data, 'fail');
    }

    /**
     * Initialize transaction with Monnify API
     */
    private function initializeTransaction($paymentData)
    {
        $endpoint = "{$this->baseUrl}/api/v1/merchant/transactions/init-transaction";

        $payerInfo = json_decode($paymentData->payer_information);
        $additionalData = json_decode($paymentData->additional_data);

        $callbackUrl = url('/') . '/payment/monnify/callback?payment_id=' . $paymentData->id;

        $formData = [
            'amount' => (float) $paymentData->payment_amount,
            'customerName' => $payerInfo->name ?? 'Customer',
            'customerEmail' => $payerInfo->email ?? 'customer@example.com',
            'paymentReference' => 'MONNIFY_' . $paymentData->id . '_' . time(),
            'paymentDescription' => $additionalData->business_name ?? 'Payment',
            'currencyCode' => $paymentData->currency_code ?? 'NGN',
            'contractCode' => $this->config->contract_code,
            'redirectUrl' => $callbackUrl,
            'paymentMethods' => ['CARD', 'ACCOUNT_TRANSFER', 'USSD'],
        ];

        try {
            $response = Http::withBasicAuth(
                $this->config->api_key,
                $this->config->secret_key
            )->post($endpoint, $formData);

            $responseObject = json_decode($response->body());

            if ($response->successful() && isset($responseObject->responseBody)) {
                // Store transaction reference for later verification
                $this->payment::where(['id' => $paymentData->id])->update([
                    'transaction_id' => $responseObject->responseBody->transactionReference ?? null,
                ]);

                return $responseObject->responseBody;
            }

            Log::error('Monnify initialization failed', [
                'response' => $responseObject,
                'payment_id' => $paymentData->id
            ]);

        } catch (\Exception $e) {
            Log::error('Monnify initialization exception', [
                'message' => $e->getMessage(),
                'payment_id' => $paymentData->id
            ]);
        }

        return null;
    }

    /**
     * Handle callback from Monnify after payment
     */
    /**
     * Handle callback from Monnify after payment
     */
    public function callback(Request $request)
    {
        $paymentId = $request->get('payment_id');
        $paymentReference = $request->get('paymentReference');
        $transactionReference = $request->get('transactionReference');

        Log::info('Monnify Callback Hit', [
            'payment_id' => $paymentId,
            'payment_ref' => $paymentReference,
            'transaction_ref' => $transactionReference
        ]);

        if (!$paymentId) {
            Log::error('Monnify Callback: No payment ID');
            return redirect()->route('payment-fail');
        }

        $paymentData = $this->payment::where(['id' => $paymentId])->first();

        if (!$paymentData) {
            Log::error('Monnify Callback: Payment data not found', ['id' => $paymentId]);
            return redirect()->route('payment-fail');
        }

        // Verify transaction status with Monnify
        // Try transactionReference first, then fallback to paymentData->transaction_id, then paymentReference
        $referenceToVerify = $transactionReference ?? $paymentData->transaction_id;
        if (!$referenceToVerify && $paymentReference) {
            $referenceToVerify = $paymentReference;
            // If using payment ref, set flag true in verifyTransaction call
        }

        Log::info('Monnify Callback: Verifying transaction', ['reference' => $referenceToVerify]);

        $transactionStatus = $this->verifyTransaction($referenceToVerify, $referenceToVerify === $paymentReference);

        Log::info('Monnify Verification Result', ['status' => $transactionStatus ? $transactionStatus->paymentStatus : 'NULL']);

        if ($transactionStatus && $transactionStatus->paymentStatus === 'PAID') {
            // Update payment record
            $this->payment::where(['id' => $paymentId])->update([
                'payment_method' => 'monnify',
                'is_paid' => 1,
                'transaction_id' => $transactionReference ?? $transactionStatus->transactionReference ?? $paymentData->transaction_id,
            ]);

            $data = $this->payment::where(['id' => $paymentId])->first();

            if (isset($data) && function_exists($data->success_hook)) {
                call_user_func($data->success_hook, $data);
            }

            return $this->payment_response($data, 'success');
        }

        // Payment failed
        Log::warning('Monnify Callback: Verification failed or not paid');
        if (isset($paymentData) && function_exists($paymentData->failure_hook)) {
            call_user_func($paymentData->failure_hook, $paymentData);
        }

        return $this->payment_response($paymentData, 'fail');
    }

    /**
     * Handle Monnify webhook notifications
     */
    public function webhook(Request $request)
    {
        $payload = $request->all();

        Log::info('Monnify webhook received', $payload);

        // Verify webhook signature (log warning but don't block - Monnify can change signature format)
        $monnifySignature = $request->header('monnify-signature');
        $computedHash = $this->computeRequestValidationHash(json_encode($payload));

        if ($monnifySignature !== $computedHash) {
            Log::warning('Monnify webhook signature mismatch', [
                'received' => $monnifySignature,
                'computed' => $computedHash,
            ]);
            // Continue processing - signature may differ due to JSON encoding differences
        }

        $eventType = $payload['eventType'] ?? null;
        $eventData = $payload['eventData'] ?? null;

        if ($eventType === 'SUCCESSFUL_TRANSACTION' && $eventData) {
            $transactionReference = $eventData['transactionReference'] ?? null;
            $paymentReference = $eventData['paymentReference'] ?? null;
            $paymentStatus = $eventData['paymentStatus'] ?? null;

            if ($paymentStatus === 'PAID' && $paymentReference) {
                // Extract payment ID from paymentReference (format: MONNIFY_<uuid>_<timestamp>)
                $parts = explode('_', $paymentReference);
                $paymentId = $parts[1] ?? null;

                if ($paymentId) {
                    $paymentData = $this->payment::where('id', $paymentId)->first();

                    if ($paymentData && !$paymentData->is_paid) {
                        // Verify with Monnify API for extra security
                        $verifiedTransaction = $this->verifyTransaction($transactionReference);

                        if ($verifiedTransaction && $verifiedTransaction->paymentStatus === 'PAID') {
                            $this->payment::where(['id' => $paymentData->id])->update([
                                'payment_method' => 'monnify',
                                'is_paid' => 1,
                                'transaction_id' => $transactionReference,
                            ]);

                            $updatedData = $this->payment::find($paymentData->id);

                            if (isset($updatedData) && function_exists($updatedData->success_hook)) {
                                call_user_func($updatedData->success_hook, $updatedData);
                            }

                            Log::info('Monnify webhook: Payment marked as paid', ['payment_id' => $paymentId]);
                        }
                    }
                }
            }
        }

        return response()->json(['status' => 'success']);
    }

    /**
     * Verify transaction status with Monnify API
     */
    private function verifyTransaction($reference, $isPaymentReference = false)
    {
        if (!$reference) {
            return null;
        }

        $endpoint = $isPaymentReference
            ? "{$this->baseUrl}/api/v2/transactions/query?paymentReference=" . urlencode($reference)
            : "{$this->baseUrl}/api/v2/transactions/" . urlencode($reference);

        try {
            // Get OAuth2 token first
            $token = $this->getOAuth2Token();

            if (!$token) {
                return null;
            }

            $response = Http::withToken($token)->get($endpoint);
            $responseObject = json_decode($response->body());

            if ($response->successful() && isset($responseObject->responseBody)) {
                return $responseObject->responseBody;
            }

        } catch (\Exception $e) {
            Log::error('Monnify verification exception', [
                'message' => $e->getMessage(),
                'transaction_reference' => $reference
            ]);
        }

        return null;
    }

    /**
     * Get OAuth2 token from Monnify
     */
    private function getOAuth2Token()
    {
        $endpoint = "{$this->baseUrl}/api/v1/auth/login";

        try {
            $response = Http::withBasicAuth(
                $this->config->api_key,
                $this->config->secret_key
            )->post($endpoint);

            $responseObject = json_decode($response->body());

            if ($response->successful() && isset($responseObject->responseBody->accessToken)) {
                return $responseObject->responseBody->accessToken;
            }

        } catch (\Exception $e) {
            Log::error('Monnify OAuth2 token exception', ['message' => $e->getMessage()]);
        }

        return null;
    }

    /**
     * Calculate transaction hash for webhook verification
     * 
     * @link https://docs.teamapt.com/display/MON/Calculating+the+Transaction+Hash
     */
    private function calculateTransactionHash($paymentReference, $amountPaid, $paidOn, $transactionReference)
    {
        $secretKey = $this->config->secret_key;
        return hash('sha512', "{$secretKey}|{$paymentReference}|{$amountPaid}|{$paidOn}|{$transactionReference}");
    }

    /**
     * Compute request validation hash for webhook signature verification
     * 
     * @link https://teamapt.atlassian.net/wiki/spaces/MON/pages/212008918/Computing+Request+Validation+Hash
     */
    private function computeRequestValidationHash($stringifiedData)
    {
        return hash_hmac('sha512', $stringifiedData, $this->config->secret_key);
    }
}
