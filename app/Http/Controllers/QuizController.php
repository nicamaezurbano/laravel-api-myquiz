<?php

namespace App\Http\Controllers;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Models\User;
use App\Models\Quiz;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

class QuizController extends Controller
{
    /**
     * Display a listing of the resource.
     */
    public function index()
    {

        try {
            
            // Retrieve user details
            $user=User::find(auth('sanctum')->user()->id);

            // Check if the user is existing
            if(empty($user))
            {
                return response()->json([
                    'message' => 'User not found',
                ], 400); 
            }

            // Retrieve created quizzes of the user
            $quizzes=Quiz::where('user_id', $user->id)->get();

            // Check if there is no quizzes created by the user
            if(empty($quizzes))
            {
                return response()->json([
                    'message' => "You don't have any created quiz.",
                ], 400); 
            }

            return response()->json([
                'data' => $quizzes,
            ], 200);

        } catch (\Exception $e) {

            return response()->json([
                'message' => $e->getMessage()
            ], 400);

        }

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
        
        try {

            // Validate request data
            $request->validate([
                'title' => 'required',
            ]);

            // Retrieve owner of the quiz
            $user=User::find(auth('sanctum')->user()->id);

            // Generate and check if the access code is existing, otherwise generate again.
            do {
                    
                $access_code = Str::random(6);
                $check_quiz=Quiz::where('access_code', $access_code)->first();

            } while (!empty($check_quiz));

            // Create the quiz
            DB::beginTransaction();
            $quiz = Quiz::create([
                'title' => $request->title,
                'access_code' => $access_code,
                'user_id' => $user->id,
            ]);
            DB::commit();

            return response()->json([
                'data' => $quiz,
                'message' => "Quiz created successfully."
            ], 200);

        } catch (\Exception $e) {

            DB::rollBack();
            return response()->json([
                'message' => $e->getMessage()
            ], 400);

        }
    }

    /**
     * Display the specified resource.
     */
    public function show(string $quiz_id)
    {
        try {
            
            // Retrieve and check if the quiz doesn't exist
            $quiz=Quiz::find($quiz_id);
            if(empty($quiz))
            {
                return response()->json([
                    'message' => 'Quiz not found.'
                ], 400);
            }

            return response()->json([
                'data' => $quiz,
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
    public function update(Request $request, string $quiz_id)
    {
        
        try {
            
            // Check if the quiz doesn't exist
            $quiz=Quiz::find($quiz_id);
            if(empty($quiz))
            {
                return response()->json([
                    'message' => 'Quiz not found.'
                ], 400);
            }

            // Only the creator of the quiz is allowed to edit
            if($quiz->user_id != auth('sanctum')->user()->id)
            {
                return response()->json([
                    'message' => 'You cannot edit this quiz.'
                ], 400);
            }

            // Validate request data
            $request->validate([
                'title' => 'required',
            ]);

            // Update quiz
            DB::beginTransaction();
            $quiz->title = $request->title;
            $quiz->save();
            DB::commit();

            return response()->json([
                'data' => $quiz,
                'message' => 'Quiz title has successfully changed.'
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
    public function destroy(string $quiz_id)
    {
        try {

            // Check if the quiz doesn't exist
            $quiz=Quiz::find($quiz_id);
            if(empty($quiz))
            {
                return response()->json([
                    'message' => 'Quiz not found.'
                ], 400);
            }

            // Only the creator of the quiz is allowed to delete
            if($quiz->user_id != auth('sanctum')->user()->id)
            {
                return response()->json([
                    'message' => 'You cannot delete this quiz.'
                ], 400);
            }

            // Delete quiz
            DB::beginTransaction();
            Quiz::destroy($quiz_id);
            DB::commit();

            return response()->json([
                'message' => 'Quiz has successfully deleted.'
            ], 200);

        } catch (\Exception $e) {
            
            DB::rollBack();
            return response()->json([
                'message' => $e->getMessage()
            ], 400);

        }
    }
}
