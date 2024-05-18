<?php

namespace App\Http\Controllers\Auth;

use App\Models\User;
use App\Http\Controllers\Controller;
use Laravel\Socialite\Facades\Socialite;
use GuzzleHttp\Exception\ClientException;

class SocialAuthController extends Controller
{
    public function redirectToProvider($provider)
    {
        $validated = $this->validateProvider($provider);
        if (!is_null($validated)) {
            return $validated;
        }
        return Socialite::driver($provider)->stateless()->redirect();
    }

    public function handleProviderCallback($provider)
    {
        $validated = $this->validateProvider($provider);
        if (!is_null($validated)) {
            return $validated;
        }
        try {
            $socialUser = Socialite::driver($provider)->stateless()->user();
        } catch (ClientException $exception) {
            return response()->json(['error' => 'Invalid credentials provided.', $exception], 422);
        }

        $user = User::firstOrCreate([
            'email' => $socialUser->getEmail(),
        ], [
            'name' => $socialUser->getName(),
            'password' => bcrypt(md5(microtime())), // Random password since social auth doesn't use it
        ]);

        $token = $user->createToken('api-token')->plainTextToken;

        return response()->json(['token' => $token, 'user' => $user], 200);
    }


    protected function validateProvider($provider)
    {
        if (!in_array($provider, ['github', 'google'])) {
            return response()->json(['error' => 'Please login using facebook, github or google'], 422);
        }
    }
}
