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
        Schema::create('order_change_amounts', function (Blueprint $table) {
            $table->id();
            $table->bigInteger('order_id');
            $table->decimal('order_amount', 20, 2)->default(0);
            $table->decimal('paid_amount', 20, 2)->default(0);
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('order_change_amounts');
    }
};
