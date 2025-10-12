// @ts-check

import { hash, verify } from "argon2";
import type { Request, Response } from "express";
import db from "../config/db";
import { createToken } from "../config/jwt";
import AppError from "../libs/utils/AppError";
import { sendError, sendSuccess } from "../libs/utils/response";
import {
	lecturerLoginSchema,
	lecturerSignupSchema,
	studentLoginSchema,
	studentSignupSchema,
} from "../schema/auth.schema";
import { COOKIE_NAME } from "../types/auth";

const isProd = process.env.NODE_ENV === "production";

// ====================== STUDENTS ======================
export const studentSignup = async (req: Request, res: Response) => {
	try {
		// 1️⃣ Validate input
		const { matricNumber, surname, level, semester } =
			await studentSignupSchema.parseAsync(req.body);

		// 2️⃣ Check if student already exists (fetch minimal fields only)
		const { data: existingStudent, error: existingError } = await db
			.from("students")
			.select("id")
			.eq("matric_number", matricNumber)
			.maybeSingle();

		if (existingError)
			throw new AppError(existingError.message || "Error checking existing student");

		if (existingStudent)
			throw new AppError("Student already exists", 400);

		// 3️⃣ Insert new student record
		const { data: student, error: insertError } = await db
			.from("students")
			.insert({
				matric_number: matricNumber.toLowerCase().trim(),
				surname: surname.trim().toLowerCase(),
				level,
				semester,
			})
			.select()
			.single();

		if (insertError || !student)
			throw new AppError(insertError?.message ?? "Student creation failed");

		// 4️⃣ Return success
		return sendSuccess(res, student, "Student created successfully", 201);
	} catch (err) {
		return sendError(err, res);
	}
};


export const studentLogin = async (req: Request, res: Response) => {
	try {
		const payload = await studentLoginSchema.parseAsync(req.body);
		const { matricNumber, surname } = payload;

		const { data: students, error } = await db
			.from("students")
			.select("*")
			.eq("matric_number", matricNumber.toLowerCase())

    // ✅ Handle errors from Supabase
    if (error) throw new AppError(error.message);

    // ✅ Handle no records
    if (!students || students.length === 0)
      throw new AppError("Student not found", 404);

    // ✅ Handle duplicate records gracefully
    if (students.length > 1) {
      console.warn(`⚠ Duplicate student records found for ${matricNumber}-> ${students}`);
		}

      // Option 1 — pick the latest (assuming "created_at" exists)
      const student = students[0];

		if (student.surname !== surname.toLowerCase()) {
			throw new AppError("you've forgotten your surname? What a bad son");
		}

		//Create token
		const token = createToken({
			id: student.id,
			role: "student",
			matricNumber: Number(student.matric_number),
		});

		//Set the JWT in a secure HTTP-only cookie
		res.cookie(COOKIE_NAME, token, {
			maxAge: 1000 * 60 * 60 * 24 * 7, // 7 days
			  httpOnly: true,
			  secure: isProd, // only HTTPS on production
			  sameSite: isProd ? "strict" : "lax",
			  path: "/", // always '/' so it's available everywhere
			  domain: isProd ? ".vercel.app" : undefined, // no domain for local dev
		});

		return sendSuccess(res, {...student, success: true}, "Student logged in", 200);
	} catch (err) {
		return sendError(err, res);
	}
};


// ====================== LECTURERS ======================

export const lecturerSignUp = async (req: Request, res: Response) => {
	try {
		// 1️⃣ Validate Input
		const { lecturerId, password, level, courses, semester, fullName, department} =
			await lecturerSignupSchema.parseAsync(req.body);

		// 2️⃣ Check if Lecturer Already Exists
		const { data: existingLecturer, error: existingError } = await db
			.from("lecturers")
			.select("id")
			.eq("lecturer_id", lecturerId.toLowerCase())
			.maybeSingle();

		if (existingError)
			throw new AppError(existingError.message || "Error checking existing lecturer");

		if (existingLecturer)
			throw new AppError("Lecturer already exists", 400);

		// 3️⃣ Hash Password
		const passwordHash = await hash(password);

		// 4️⃣ Start Transaction (Atomic Insert)
		const { data: newLecturer, error: lecturerError } = await db
			.from("lecturers")
			.insert({
				lecturer_id: lecturerId.toLowerCase(),
				password: passwordHash,
				courses,
				level,
				semester,
				full_name: fullName,
				department
			})
			.select()
			.single();

		if (lecturerError || !newLecturer)
			throw new AppError(lecturerError?.message ?? "Failed to create lecturer");

		// 5️⃣ Batch Insert Course Relations (safe, single call)
		const courseLinks = courses.map((courseId) => ({
			course_id: courseId,
			lecturer_id: newLecturer.id,
		}));

		const { error: linkError } = await db
			.from("lecturer_courses")
			.insert(courseLinks);

		if (linkError)
			throw new AppError(linkError.message ?? "Failed to assign courses");

		// 6️⃣ Return Success Response
		return sendSuccess(res, newLecturer, "Lecturer created successfully", 201);

	} catch (error) {
		return sendError(error, res);
	}
};
export const lecturerLogin = async (req: Request, res: Response) => {
	try {
		const { password, lecturerId } = await lecturerLoginSchema.parseAsync(
			req.body,
		);

		const { data: lecturers, error } = await db
			.from("lecturers")
			.select("*")
			.eq("lecturer_id", lecturerId.toLowerCase())

		// ✅ Handle errors from Supabase
    if (error) throw new AppError(error.message);

    // ✅ Handle no records
    if (!lecturers || lecturers.length === 0)
      throw new AppError("lecturer not found", 404);

    // ✅ Handle duplicate records gracefully
    if (lecturers.length > 1) {
      console.warn(`⚠ Duplicate lecturer records found for ${lecturerId}-> ${lecturers}`);
		}

      // Option 1 — pick the latest (assuming "created_at" exists)
      const lecturer = lecturers[0];

		if (error) throw new AppError(error);
		if (!lecturer) throw new AppError(`No Lecturer with id: ${lecturerId}`);

		const validPassword = await verify(lecturer.password, password);
		if (!validPassword) {
			throw new AppError("The Password you entered wasn't correct");
		}

		//Create token
		const token = createToken({
			id: lecturer.id,
			role: "lecturer",
			lecturerId: Number(lecturer.lecturer_id),
		});

		//Set the JWT in a secure HTTP-only cookie
		res.cookie(COOKIE_NAME, token, {
		  maxAge: 1000 * 60 * 60 * 24 * 7, // 7 days
		  httpOnly: true,
		  secure: isProd, // only HTTPS on production
		  sameSite: isProd ? "strict" : "lax",
		  path: "/", // always '/' so it's available everywhere
		  domain: isProd ? ".vercel.app" : undefined, // no domain for local dev
		});

		return sendSuccess(res, {...lecturer, success: true}, "Lecturer logged in", 200);
	} catch (error) {
		return sendError(error, res);
	}
};

export const logout = async (_: Request, res: Response) => {
	try {
		res.clearCookie(COOKIE_NAME);
		return sendSuccess(res, null, "Logged out successfully");
	} catch (error) {
		return sendError(error, res);
	}
};

//
