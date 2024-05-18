<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\Auth\SocialAuthController;

Route::middleware(['auth:sanctum'])->get('/user', function (Request $request) {
    return $request->user();
});

Route::get('auth/redirect/{provider}', [SocialAuthController::class, 'redirectToProvider']);
Route::get('auth/callback/{provider}', [SocialAuthController::class, 'handleProviderCallback']);

