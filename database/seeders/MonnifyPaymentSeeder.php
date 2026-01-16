<?php

namespace Database\Seeders;

use App\Models\Setting;
use Illuminate\Database\Seeder;

class MonnifyPaymentSeeder extends Seeder
{
    /**
     * Run the database seeds.
     */
    public function run(): void
    {
        // Check if monnify already exists
        $exists = Setting::where('key_name', 'monnify')
            ->where('settings_type', 'payment_config')
            ->exists();

        if (!$exists) {
            Setting::create([
                'key_name' => 'monnify',
                'live_values' => json_encode([
                    'gateway' => 'monnify',
                    'mode' => 'test',
                    'status' => '0',
                    'api_key' => '',
                    'secret_key' => '',
                    'contract_code' => '',
                ]),
                'test_values' => json_encode([
                    'gateway' => 'monnify',
                    'mode' => 'test',
                    'status' => '0',
                    'api_key' => '',
                    'secret_key' => '',
                    'contract_code' => '',
                ]),
                'settings_type' => 'payment_config',
                'mode' => 'test',
                'is_active' => 0,
                'additional_data' => json_encode([
                    'gateway_title' => 'Monnify',
                    'gateway_image' => '',
                ]),
            ]);
        }
    }
}
