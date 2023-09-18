<?php

namespace App\Http\Controllers;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;

class UserController extends Controller
{
    /**
     * Generate user token if successfully loged in.
     */
    public function login(Request $request)
    {
        try {

            // Validate request data
            $request->validate([
                'email' => ['required','email','regex:/^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/'],
                'password' => 'required|min:8|regex:/^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$ %^&*-]).*$/',
            ]);

            // Check if the user is not registered
            $user = User::where('email', $request->email)->first();
            if (!$user) {
                return response([
                    'message' => 'Email not exists. Please try again.'
                ], 401); //401 status code means unauthorized
            }
            
            // Check if the password matched
            if (!Hash::check($request->password, $user->password)) {
                return response([
                    'message' => 'Incorrect password. Please try again.'
                ], 401); 
            }

            // Generate a token
            DB::beginTransaction();
            $token = $user->createToken($user->email)->plainTextToken;
            DB::commit();

            // Return data and message
            return response()->json([
                'data' => [
                    'first_name' => $user->first_name,
                    'last_name' => $user->last_name,
                    'email' => $user->email,
                    'token' => $token,
                ],
                'message' => "Login successfully."
            ], 200);

        } catch (\Exception $e) {

            // The changes will rollback and will not be saved.
            DB::rollBack();
            return response()->json([
                'message' => $e->getMessage()
            ], 400);

        }

    }

    /**
     * Display a listing of the resource.
     */
    public function index()
    {
        //
    }

    /**
     * Show the form for creating a new resource.
     */
    public function create()
    {
        //
    }

    /**
     * Store a newly created resource in storage.
     */
    public function store(Request $request)
    {
        
        // Successfully creates user account.
        try {

            // Validate request data
            $request->validate([
                'first_name' => 'required',
                'last_name' => 'required',
                'email' => ['required','email','unique:users','regex:/^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/'],
                'password' => 'required|min:8|regex:/^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$ %^&*-]).*$/',
            ]);
            /**
             *  Password rule:
             *      -minimum eight characters,
             *      -at least one upper case English letter, 
             *      -one lower case English letter, 
             *      -one number and 
             *      -one special character:  #?!@$ %^&*-
            */

            // Create user account
            DB::beginTransaction();
            $user = User::create([
                'first_name' => $request->first_name,
                'last_name' => $request->last_name,
                'email' => $request->email,
                'password' => bcrypt($request->password)
            ]);
            DB::commit();

            return response()->json([
                'data' => $user,
                'message' => "Your account created successfully.",
            ], 200);

        } catch(\Exception $e) {

            // The changes will rollback and will not be saved.
            DB::rollBack();
            return response()->json([
                'message' => $e->getMessage()
            ], 400);
            // 400 status code means bad request

        }
    }

    /**
     * Display the specified resource.
     */
    public function show()
    {
        try {
            
            // Retrieve user details
            $user=User::find(auth('sanctum')->user()->id);

            if(!$user)
            {
                return response()->json([
                    'message' => 'User not found.'
                ], 400);
            }

            return response()->json([
                'data' => $user
            ], 200);

        } catch (\Exception $e) {

            return response()->json([
                'message' => $e->getMessage()
            ], 400);

        }
    }

    /**
     * Show the form for editing the specified resource.
     */
    public function edit(string $id)
    {
        //
    }

    /**
     * Update the specified resource in storage.
     */
    public function update(Request $request)
    {
        try {
            
            // Validate request data
            $request->validate([
                'first_name' => 'required',
                'last_name' => 'required',
            ]);
    
            // Update user details
            DB::beginTransaction();

            $user=User::find(auth('sanctum')->user()->id);
            $user->first_name = $request->first_name;
            $user->last_name = $request->last_name;
            $user->save();

            DB::commit();

            return response()->json([
                'data' => $user,
                'message' => 'You name has successfully changed.'
            ], 200);

        } catch (\Exception $e) {
            
            DB::rollBack();
            return response()->json([
                'message' => $e->getMessage()
            ], 400);

        }
    }

    /**
     * Update the specified resource in storage.
     */
    public function change_password(Request $request)
    {
        try {
            
            // Validate request data
            $request->validate([
                'old_password' => 'required|min:8|regex:/^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$ %^&*-]).*$/',
                'new_password' => 'required|min:8|regex:/^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$ %^&*-]).*$/',
            ]);
    
            // Check if the password don't matched
            $user=User::find(auth('sanctum')->user()->id);

            if (!Hash::check($request->old_password, $user->password)) {
                return response([
                    'message' => "Old password doesn't match. Please try again."
                ], 401); 
            }

            // Update user's password
            DB::beginTransaction();
            $user->password = bcrypt($request->new_password);
            $user->save();
            DB::commit();

            return response()->json([
                'data' => $user,
                'message' => 'Password has successfully changed.'
            ], 200);

        } catch (\Exception $e) {
            
            DB::rollBack();
            return response()->json([
                'message' => $e->getMessage()
            ], 400);

        }
    }

    /**
     * Remove the specified resource from storage.
     */
    public function destroy(string $id)
    {
        //
    }


    /**
     * Remove token assigned to a user.
     */
    public function logout(Request $request)
    {
        try {
            // Delete the user's valid token
            DB::beginTransaction();
            auth()->user()->tokens()->delete();
            DB::commit();

            return response()->json([
                'message' => 'User logged out.'
            ], 200);

        } catch(\Exception $e) {
            DB::rollBack();
            return response()->json([
                'message' => $e->getMessage()
            ], 400);

        }
        
    }
}
