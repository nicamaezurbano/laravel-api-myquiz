<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\UserController;
use App\Http\Controllers\QuizController;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider and all of them will
| be assigned to the "api" middleware group. Make something great!
|
*/

Route::middleware('auth:sanctum')->get('/user', function (Request $request) {
    return $request->user();
});

// Route::get('/user', [UserController::class, 'index']);
Route::post('/register', [UserController::class, 'store']);
Route::post('/login', [UserController::class, 'login']);

// Protected Routes
Route::middleware(['auth:sanctum'])->group(function () {
    Route::get('/user/show', [UserController::class, 'show']);
    Route::post('/user/update', [UserController::class, 'update']);
    Route::post('/user/change_password', [UserController::class, 'change_password']);
    Route::post('/logout', [UserController::class, 'logout']);
    
    Route::get('/quiz/index', [QuizController::class, 'index']);
    Route::post('/quiz/store', [QuizController::class, 'store']);
    Route::get('/quiz/show/{quiz_id}', [QuizController::class, 'show']);
    Route::post('/quiz/update/{quiz_id}', [QuizController::class, 'update']);
    Route::post('/quiz/delete/{quiz_id}', [QuizController::class, 'destroy']);
});