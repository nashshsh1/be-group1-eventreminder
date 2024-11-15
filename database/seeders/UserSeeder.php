<?php

namespace Database\Seeders;

use Illuminate\Database\Seeder;
use App\Models\User;
use Illuminate\Support\Facades\Hash;

class UserSeeder extends Seeder
{
    public function run()
    {
        User::create([
            'name' => 'Jay Nashvel',
            'email' => 'nash@gmail.com',
            'password' => Hash::make('password'),
        ]);

        User::factory()->count(20)->create();
    }
}


