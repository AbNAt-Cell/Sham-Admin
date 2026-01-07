<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::table('delivery_charge_setups', function (Blueprint $table) {
            $table->tinyInteger('free_delivery_over_status')->default(0);
            $table->double('free_delivery_over_amount')->default(0);
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::table('delivery_charge_setups', function (Blueprint $table) {
            $table->removeColumn('free_delivery_over_status');
            $table->removeColumn('free_delivery_over_amount');
        });
    }
};
