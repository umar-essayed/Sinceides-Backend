import express from 'express';
import { Request, Response, NextFunction, Router } from 'express';
import * as admin from 'firebase-admin';
import { Bucket } from '@google-cloud/storage'; // أضف هذا الاستيراد
import path from "path";
import bcrypt from 'bcryptjs';
import passport from 'passport';
import { Strategy as LocalStrategy } from 'passport-local';
import * as jwt from 'jsonwebtoken';
import multer, { FileFilterCallback } from 'multer';
import helmet from 'helmet';
import cors from 'cors';
import rateLimit from "express-rate-limit";
import { Strategy as JwtStrategy, ExtractJwt } from "passport-jwt";
import compression from 'compression';
import { z, ZodError } from 'zod';
import winston from 'winston';
import morgan from 'morgan';
import { v4 as uuidv4 } from 'uuid';
import dayjs from 'dayjs';
import Redis from 'ioredis';
import fs, { PathLike, MakeDirectoryOptions, WriteFileOptions, PathOrFileDescriptor } from "fs";
import 'express-async-errors';
import swaggerUi from 'swagger-ui-express';
import swaggerJsdoc from 'swagger-jsdoc';
import PDFDocument from 'pdfkit';
import * as csv from "csv-writer";
import * as dotenv from 'dotenv';
dotenv.config();
// Extend Express Request type
declare global {
  namespace Express {
    interface User extends BaseEntity {
      name: string;
      email: string;
      passwordHash: string;
      phoneNumber: string;
      dateOfBirth: string;
      country: string;
      gender: Gender;
      role: Role;
      profilePictureUrl: string | null;
      enrolledCourseIds: string[];
      isBlocked: boolean;
      assignedHrId?: string | null;
      challengeSubmissions?: { [challengeId: string]: UserChallengeSubmission };

    }

    interface Request {
      user?: User;
    }

    interface Multer {
      File: {
        fieldname: string;
        originalname: string;
        encoding: string;
        mimetype: string;
        size: number;
        destination: string;
        filename: string;
        path: string;
        buffer: Buffer;
      };
    }
  }
}
let firebaseProjectId: string; // أضف هذا في أعلى الملف


// مسار ملف الـ JSON
const serviceAccountPath = path.resolve(__dirname, "config", "sinceidesv2-firebase-adminsdk-fbsvc-22bac469f1.json");

// التحقق من وجود الملف
if (!fs.existsSync(serviceAccountPath)) {
    console.error("❌ Firebase service account file not found at:", serviceAccountPath);
    process.exit(1);
}

// استدعاء الملف
const serviceAccount = require(serviceAccountPath);

console.log("Initializing Firebase...");
try {

  if (admin.apps.length === 0) {
    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount),
      databaseURL: `https://${serviceAccount.project_id}.firebaseio.com`,
      storageBucket: `${serviceAccount.project_id}.appspot.com` // أضف هذا
    });
    firebaseProjectId = serviceAccount.project_id;
    console.log("✅ Firebase Admin initialized successfully");
    console.log(`Project ID: ${serviceAccount.project_id}`);
    console.log(`Storage Bucket: ${serviceAccount.project_id}.appspot.com`);
  } else {
    // استخدام التطبيق الحالي إذا كان موجودًا
    admin.app();
    console.log("✅ Using existing Firebase app");
  }
} catch (error) {
    console.error("❌ Firebase Admin initialization error:", error);
    process.exit(1);
}

// Initialize Firebase Storage
class FirebaseStorageService {
  constructor(private bucket: Bucket) {}

  async uploadFile(buffer: Buffer, fileName: string, destinationPath: string = 'uploads'): Promise<string> {
    const filePath = `${destinationPath}/${Date.now()}_${fileName}`;
    const file = this.bucket.file(filePath);
    
    await file.save(buffer, {
      metadata: {
        contentType: this.getContentType(fileName),
      },
    });

    // Make the file publicly accessible
    await file.makePublic();

    // Return the public URL
    return `https://storage.googleapis.com/${this.bucket.name}/${filePath}`;
  }

  async deleteFile(fileUrl: string): Promise<boolean> {
    try {
      // Extract file path from URL
      const urlParts = fileUrl.split('/');
      const filePath = urlParts.slice(4).join('/'); // Remove the https://storage.googleapis.com/bucket-name/ part
      
      const file = this.bucket.file(filePath);
      await file.delete();
      return true;
    } catch (error) {
      logger.error('Error deleting file from Firebase Storage:', error);
      return false;
    }
  }

  async uploadFromPath(filePath: string, destinationPath: string = 'uploads'): Promise<string> {
    const fileName = path.basename(filePath);
    const fileBuffer = fs.readFileSync(filePath);
    return this.uploadFile(fileBuffer, fileName, destinationPath);
  }

  private getContentType(fileName: string): string {
    const extension = fileName.split('.').pop()?.toLowerCase();
    const contentTypes: { [key: string]: string } = {
      'jpg': 'image/jpeg',
      'jpeg': 'image/jpeg',
      'png': 'image/png',
      'gif': 'image/gif',
      'webp': 'image/webp',
      'pdf': 'application/pdf',
      'doc': 'application/msword',
      'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
      'zip': 'application/zip',
      'mp4': 'video/mp4',
      'mov': 'video/quicktime',
      'avi': 'video/x-msvideo',
    };
    
    return contentTypes[extension || ''] || 'application/octet-stream';
  }
}


const bucket = admin.storage().bucket() as unknown as Bucket;
const firebaseStorageService = new FirebaseStorageService(bucket);


const db = admin.firestore();
const firestoreEnabled = process.env.FIRESTORE_ENABLED !== 'false';
const firestorePrefix = process.env.FIRESTORE_PREFIX || 'prod';

// Redis setup


// تهيئة Redis مباشرة باستخدام بيانات Upstash
const redisClient = new Redis({
  host: "premium-lobster-46946.upstash.io",
  port: 6379,
  password: "AbdiAAIncDE1MDE3MjRiNTRiYzQ0ZWUyOGY0Y2RkMjJkZjRmMDQyN3AxNDY5NDY",
  db: 0,
  tls: {}, // ضروري للاتصال بـ Upstash عبر SSL
});

// مدة صلاحية القيم
const REDIS_TTL_SINGLE = 300; // 5 دقائق
const REDIS_TTL_LIST = 60;    // 1 دقيقة


// Environment variables
const PORT = parseInt(process.env.PORT || '4000');
const JWT_SECRET = process.env.JWT_SECRET || 'secret';
const JWT_ACCESS_EXPIRY = process.env.JWT_ACCESS_EXPIRY || '15m';
const JWT_REFRESH_EXPIRY = process.env.JWT_REFRESH_EXPIRY || '7d';

const UPLOAD_DIR = '/tmp/';
const DATA_DIR = '/tmp/';
const LOG_DIR = '/tmp/';



// Patch mkdirSync safely


// ---- Patch mkdirSync ----
const origMkdirSync: typeof fs.mkdirSync = fs.mkdirSync.bind(fs);
fs.mkdirSync = function (
  path: PathLike,
  options?: MakeDirectoryOptions & { recursive?: boolean }
): string | undefined {
  if (typeof path === "string" && path.includes("/var/task/src/uploads")) {
    console.warn("⚠️ Blocked attempt to mkdir in forbidden path:", path);
    return path;
  }
  return origMkdirSync(path, options as any);
} as typeof fs.mkdirSync;

// ---- Patch writeFileSync ----
const origWriteFileSync: typeof fs.writeFileSync = fs.writeFileSync.bind(fs);
fs.writeFileSync = function (
  file: PathOrFileDescriptor,
  data: string | NodeJS.ArrayBufferView,
  options?: WriteFileOptions
): void {
  if (typeof file === "string" && file.includes("/var/task/src/uploads")) {
    console.warn("⚠️ Blocked attempt to write in forbidden path:", file);
    return;
  }
  return origWriteFileSync(file, data, options);
} as typeof fs.writeFileSync;

// Logger setup
const transports: winston.transport[] = [
  new winston.transports.Console()
];

if (process.env.NODE_ENV !== 'production') {
  // في بيئة التطوير، استخدم Console فقط لتجنب مشاكل Vercel
  transports.push(
    new winston.transports.Console({ level: 'error' }),
    new winston.transports.Console({ level: 'info' })
  );
}

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports
});

// Custom error class
class HttpError extends Error {
  constructor(public statusCode: number, public message: string, public details?: any) {
    super(message);
  }
}

// Enums
enum Gender {
  MALE = 'Male',
  FEMALE = 'Female',
  OTHER = 'Other',
}

enum Role {
  ADMIN = 'admin',
  INSTRUCTOR = 'instructor',
  STUDENT = 'student',
  HR = 'hr',
  SUPPORT = 'support',
}

enum Level {
  BEGINNER = 'Beginner',
  INTERMEDIATE = 'Intermediate',
  ADVANCED = 'Advanced',
}

enum Status {
  OPEN = 'open',
  CLOSED = 'closed',
  PENDING = 'pending',
}

enum ExportFormat {
  CSV = 'csv',
  PDF = 'pdf',
}

// أضف هذه الأنماط والإنترفيسات بعد الإنترفيسات الحالية
enum ChallengeType {
  DAILY = 'daily',
  WEEKLY = 'weekly', 
  MONTHLY = 'monthly'
}

enum ChallengeStatus {
  UPCOMING = 'upcoming',
  ACTIVE = 'active',
  ENDED = 'ended'
}
enum ExamType {
  QUIZ = 'quiz',
  MIDTERM = 'midterm',
  FINAL = 'final'
}

enum QuestionType {
  MULTIPLE_CHOICE = 'multiple_choice',
  TRUE_FALSE = 'true_false',
  ESSAY = 'essay'
}

enum LearningStyle {
  VISUAL = 'visual',
  AUDITORY = 'auditory',
  KINESTHETIC = 'kinesthetic',
  READING_WRITING = 'reading_writing'
}

enum ProficiencyLevel {
  NOVICE = 'novice',
  INTERMEDIATE = 'intermediate',
  ADVANCED = 'advanced',
  EXPERT = 'expert'
}


// Interfaces
interface BaseEntity {
  id: string;
  createdAt: string;
  updatedAt: string;
  deletedAt: string | null;
}

interface User extends BaseEntity {
  name: string;
  email: string;
  passwordHash: string;
  phoneNumber: string;
  dateOfBirth: string;
  country: string;
  gender: Gender;
  role: Role;
  profilePictureUrl: string | null;
  enrolledCourseIds: string[];
  isBlocked: boolean;
  assignedHrId?: string | null;
  challengeSubmissions?: { [challengeId: string]: UserChallengeSubmission };

}

// عدّل واجهة Course في الخادم
interface Course extends BaseEntity {
  title: string;
  description: string;
  thumbnailUrl: string;
  instructorId: string;
  totalLessons: number;
  categoryId: string;
  language: string;
  level: Level;
  studentIds: string[];
  tags: string[];
  firstPublishDate: string | null;
  // الحقول الجديدة
  price?: number;
  duration?: number;
  rating?: number;
  enrollmentCount?: number;
  isPublished?: boolean;
}

interface Lesson extends BaseEntity {
  courseId: string;
  lessonNumber: number;
  title: string;
  description: string;
  videoUrl: string;
  attachments: string[];
  thumbnailUrl: string;
  instructorId: string;
  durationMinutes: number;
}

interface Exam extends BaseEntity {
  courseId: string;
  lessonId?: string;
  title: string;
  description: string;
  type: ExamType;
  durationMinutes: number;
  passingScore: number;
  questions: Question[];
  maxAttempts: number;
  availableFrom?: string;
  availableUntil?: string;
}

interface Question {
  id: string;
  type: QuestionType;
  question: string;
  options?: string[];
  correctAnswer?: number | string;
  points: number;
  explanation?: string;
}

interface ExamAttempt extends BaseEntity {
  userId: string;
  examId: string;
  answers: { questionId: string, answer: string | number }[];
  score: number;
  passed: boolean;
  timeSpent: number;
}

interface Certificate extends BaseEntity {
  userId: string;
  courseId: string;
  issueDate: string;
  certificateUrl: string;
  verificationCode: string;
  grade?: string;
}

interface Category extends BaseEntity {
  name: string;
  description: string;
}

interface Enrollment extends BaseEntity {
  userId: string;
  courseId: string;
  lessonsCompleted: string[];
  rating: number | null;
  completedAt: string | null;
}

interface Message {
  id: string;
  senderId: string;
  content: string;
  timestamp: string;
  read: boolean;
}

interface SupportConversation extends BaseEntity {
  userId: string;
  supportId: string | null;
  status: Status;
  messages: Message[];
}

interface RefreshToken extends BaseEntity {
  userId: string;
  token: string;
  expiresAt: string;
  createdAt: string;
}

interface ActivityLog extends BaseEntity {
  userId: string;
  action: string;
  resourceType: string;
  resourceId: string | null;
  details: Record<string, any>;
}

interface UserReport {
  user: UserDTO;
  enrollments: EnrollmentDTO[];
  progress: {
    totalCourses: number;
    completedCourses: number;
    totalLessons: number;
    completedLessons: number;
  };
  supportConversations: SupportConversationDTO[];
}

interface AdminDashboard {
  blockedUsers: number;
  deletedItems: {
    users: number;
    courses: number;
    lessons: number;
    categories: number;
    enrollments: number;
    conversations: number;
  };
  supportMetrics: {
    openConversations: number;
    closedConversations: number;
    averageMessages: number;
  };
  courseAggregates: {
    totalCourses: number;
    averageStudents: number;
    topCourses: CourseDTO[];
  };
}

interface ChallengeQuestion {
  id: string;
  question: string;
  options: string[];
  correctAnswer: number;
  points: number;
  explanation?: string;
}

interface LeaderboardEntry {
  userId: string;
  score: number;
  timeSpent: number;
  completedAt: string;
}

interface Roadmap extends BaseEntity {
  title: string;
  description: string;
  thumbnailUrl: string;
  introVideoUrl: string;
  estimatedHours: number;
  difficulty: Level;
  categoryId: string;
  courseIds: string[];
  enrolledUserIds: string[];
  isPublished: boolean;
  tags: string[];
  instructorId: string;
  objectives: string[];
  prerequisites: string[];
}

interface Challenge extends BaseEntity {
  title: string;
  description: string;
  type: ChallengeType;
  status: ChallengeStatus;
  startDate: string;
  endDate: string;
  questions: ChallengeQuestion[];
  totalPoints: number;
  durationMinutes: number;
  participants: string[];
  leaderboard: LeaderboardEntry[];
}

interface UserChallengeSubmission {
  answers: number[];
  score: number;
  timeSpent: number;
  completedAt: string;
  rank?: number;
}
interface LearningProfile extends BaseEntity {
  userId: string;
  learningStyle: LearningStyle;
  proficiencyLevel: ProficiencyLevel;
  preferredDifficulty: Level;
  dailyStudyTime: number; // in minutes
  strengths: string[];
  weaknesses: string[];
  lastActiveTime: string; // time of day when user is most active
  progressRate: number; // average progress per week
}

interface Recommendation extends BaseEntity {
  userId: string;
  courseIds: string[];
  roadmapIds: string[];
  challengeIds: string[];
  confidenceScore: number;
  reason: string;
}

// أضف هذه الواجهة مع الواجهات الأخرى
interface AtRiskStudent {
  userId: string;
  userName: string;
  email: string;
  completionProbability: number;
  riskFactors: string[];
  recommendedInterventions: string[];
  lastActivity: string;
}
interface LearningPath extends BaseEntity {
  userId: string;
  goal: string;
  estimatedCompletion: string;
  courses: {
    courseId: string;
    order: number;
    expectedStart: string;
    expectedEnd: string;
    status: 'pending' | 'in-progress' | 'completed';
  }[];
  progress: number;
}

interface EngagementMetric extends BaseEntity {
  userId: string;
  courseId: string;
  totalTimeSpent: number;
  videoCompletionRate: number;
  quizAttempts: number;
  discussionParticipation: number;
  resourceDownloads: number;
  lastEngagement: string;
}

interface AdaptiveContent extends BaseEntity {
  courseId: string;
  lessonId: string;
  difficultyVariants: {
    level: Level;
    content: string;
    resources: string[];
    durationMinutes: number;
  }[];
}

interface PredictiveAnalytic extends BaseEntity {
  userId: string;
  courseId: string;
  completionProbability: number;
  predictedGrade: string;
  riskFactors: string[];
  recommendedInterventions: string[];
}

interface StudyGroup extends BaseEntity {
  courseId: string;
  name: string;
  memberIds: string[];
  meetingSchedule: {
    day: string;
    time: string;
    frequency: 'weekly' | 'biweekly';
  };
  sharedResources: string[];
  discussionThreads: {
    id: string;
    userId: string;
    message: string;
    timestamp: string;
    replies: {
      userId: string;
      message: string;
      timestamp: string;
    }[];
  }[];
}

interface PeerReview extends BaseEntity {
  assignmentId: string;
  reviewerId: string;
  revieweeId: string;
  criteria: {
    name: string;
    score: number;
    feedback: string;
  }[];
  overallScore: number;
  overallFeedback: string;
  submittedAt: string;
}

interface NotificationPreference extends BaseEntity {
  userId: string;
  notificationTypes: {
    type: string;
    enabled: boolean;
    preferredTime?: string;
    channel: 'email' | 'push' | 'both';
  }[];
  quietHours: {
    start: string;
    end: string;
  };
  weeklyDigest: boolean;
  activitySummary: boolean;
}



// أضف الـ DTOs بعد الـ DTOs الحالية
class RoadmapDTO {
  constructor(
    public id: string,
    public title: string,
    public description: string,
    public thumbnailUrl: string,
    public introVideoUrl: string,
    public estimatedHours: number,
    public difficulty: Level,
    public categoryId: string,
    public courseIds: string[],
    public enrolledUserIds: string[],
    public isPublished: boolean,
    public tags: string[],
    public instructorId: string,
    public objectives: string[],
    public prerequisites: string[],
    public progress?: {
      completedCourses: number;
      totalCourses: number;
      percentage: number;
    }
  ) {}
}

class ChallengeDTO {
  constructor(
    public id: string,
    public title: string,
    public description: string,
    public type: ChallengeType,
    public status: ChallengeStatus,
    public startDate: string,
    public endDate: string,
    public questions: ChallengeQuestion[],
    public totalPoints: number,
    public durationMinutes: number,
    public participants: number,
    public userSubmission?: UserChallengeSubmission
  ) {}
}
// DTOs
class UserDTO {
  constructor(
    public id: string,
    public name: string,
    public email: string,
    public phoneNumber: string,
    public dateOfBirth: string,
    public country: string,
    public gender: Gender,
    public role: Role,
    public profilePictureUrl: string | null,
    public isBlocked: boolean,
    public createdAt: string,
    public updatedAt: string,
    public assignedHrId?: string | null
  ) {}
}

class CourseDTO {
  constructor(
    public id: string,
    public title: string,
    public description: string,
    public thumbnailUrl: string,
    public instructorId: string,
    public totalLessons: number,
    public categoryId: string,
    public language: string,
    public level: Level,
    public tags: string[],
    public studentIds: string[],
    public firstPublishDate: string | null,
    public createdAt: string,
    public updatedAt: string
  ) {}
}

class LessonDTO {
  constructor(
    public id: string,
    public courseId: string,
    public lessonNumber: number,
    public title: string,
    public description: string,
    public videoUrl: string,
    public attachments: string[],
    public thumbnailUrl: string,
    public instructorId: string,
    public durationMinutes: number,
    public createdAt: string,
    public updatedAt: string
  ) {}
}

class CategoryDTO {
  constructor(
    public id: string,
    public name: string,
    public description: string,
    public createdAt: string,
    public updatedAt: string
  ) {}
}

class EnrollmentDTO {
  constructor(
    public id: string,
    public userId: string,
    public courseId: string,
    public lessonsCompleted: string[],
    public rating: number | null,
    public completedAt: string | null,
    public createdAt: string,
    public updatedAt: string
  ) {}
}

class SupportConversationDTO {
  constructor(
    public id: string,
    public userId: string,
    public supportId: string | null,
    public status: Status,
    public messages: Message[],
    public createdAt: string,
    public updatedAt: string
  ) {}
}

class ExamDTO {
  constructor(
    public id: string,
    public courseId: string,
    public lessonId: string | null,
    public title: string,
    public description: string,
    public type: ExamType,
    public durationMinutes: number,
    public passingScore: number,
    public questions: Question[],
    public maxAttempts: number,
    public availableFrom: string | null,
    public availableUntil: string | null,
    public createdAt: string,
    public updatedAt: string
  ) {}
}

class ExamAttemptDTO {
  constructor(
    public id: string,
    public userId: string,
    public examId: string,
    public score: number,
    public passed: boolean,
    public timeSpent: number,
    public createdAt: string,
    public updatedAt: string
  ) {}
}

class CertificateDTO {
  constructor(
    public id: string,
    public userId: string,
    public courseId: string,
    public issueDate: string,
    public certificateUrl: string,
    public verificationCode: string,
    public grade: string | null,
    public createdAt: string,
    public updatedAt: string
  ) {}
}
// Base Repository
class BaseRepository<T extends BaseEntity> {
  constructor(protected collectionName: string) {}

  protected getCollection() {
    return db.collection(`${firestorePrefix}_${this.collectionName}`);
  }

  async create(data: Omit<T, keyof BaseEntity>): Promise<T> {
    const id = uuidv4();
    const now = dayjs().toISOString();
    const entity = {
      ...data,
      id,
      createdAt: now,
      updatedAt: now,
      deletedAt: null,
    } as T;

    await this.getCollection().doc(id).set(entity);
    return entity;
  }

  async findById(id: string, includeDeleted = false): Promise<T | null> {
    const doc = await this.getCollection().doc(id).get();
    if (!doc.exists) return null;
    const data = doc.data() as T;
    if (!includeDeleted && data.deletedAt) return null;
    return data;
  }

  async findMany(
    filters: Record<string, any> = {},
    includeDeleted = false,
    limit = 10,
    cursor?: string
  ): Promise<{ data: T[]; nextCursor: string | null }> {
    let query: admin.firestore.Query = this.getCollection();

    // Apply filters
    Object.entries(filters).forEach(([key, value]) => {
      if (value !== undefined) {
        query = query.where(key, '==', value);
      }
    });

    if (!includeDeleted) {
      query = query.where('deletedAt', '==', null);
    }

    if (cursor) {
      const cursorDoc = await this.getCollection().doc(cursor).get();
      query = query.startAfter(cursorDoc);
    }

    query = query.limit(limit);

    const snapshot = await query.get();
    const data = snapshot.docs.map(doc => doc.data() as T);
    const nextCursor = snapshot.docs.length === limit ? snapshot.docs[snapshot.docs.length - 1].id : null;

    return { data, nextCursor };
  }

  async update(id: string, data: Partial<Omit<T, keyof BaseEntity>>): Promise<T | null> {
    const docRef = this.getCollection().doc(id);
    const updateData = {
      ...data,
      updatedAt: dayjs().toISOString(),
    };

    await docRef.update(updateData);
    const updatedDoc = await docRef.get();
    return updatedDoc.exists ? (updatedDoc.data() as T) : null;
  }

  async softDelete(id: string): Promise<boolean> {
    const result = await this.update(id, { deletedAt: dayjs().toISOString() } as any);
    return !!result;
  }

  async restore(id: string): Promise<boolean> {
    const result = await this.update(id, { deletedAt: null } as any);
    return !!result;
  }

  async permanentDelete(id: string): Promise<boolean> {
    await this.getCollection().doc(id).delete();
    return true;
  }
}

// Entity Repositories
class UserRepository extends BaseRepository<User> {
  constructor() {
    super('users');
  }

  async findByEmail(email: string): Promise<User | null> {
    const snapshot = await this.getCollection().where('email', '==', email).limit(1).get();
    if (snapshot.empty) return null;
    const user = snapshot.docs[0].data() as User;
    if (user.deletedAt) return null;
    return user;
  }

  async blockUser(id: string): Promise<boolean> {
    return !!(await this.update(id, { isBlocked: true }));
  }

  async unblockUser(id: string): Promise<boolean> {
    return !!(await this.update(id, { isBlocked: false }));
  }

  async assignHr(instructorId: string, hrId: string): Promise<boolean> {
    return !!(await this.update(instructorId, { assignedHrId: hrId }));
  }
}

class CourseRepository extends BaseRepository<Course> {
  constructor() {
    super('courses');
  }

  async incrementTotalLessons(courseId: string): Promise<void> {
    const docRef = this.getCollection().doc(courseId);
    await db.runTransaction(async transaction => {
      const doc = await transaction.get(docRef);
      if (!doc.exists) throw new Error('Course not found');
      const current = doc.data()?.totalLessons || 0;
      transaction.update(docRef, { totalLessons: current + 1 });
    });
  }

  async decrementTotalLessons(courseId: string): Promise<void> {
    const docRef = this.getCollection().doc(courseId);
    await db.runTransaction(async transaction => {
      const doc = await transaction.get(docRef);
      if (!doc.exists) throw new Error('Course not found');
      const current = doc.data()?.totalLessons || 0;
      transaction.update(docRef, { totalLessons: Math.max(0, current - 1) });
    });
  }

  async getTopCourses(limit = 5): Promise<Course[]> {
    const snapshot = await this.getCollection()
      .orderBy('studentIds', 'desc')
      .limit(limit)
      .get();

    return snapshot.docs.map(doc => doc.data() as Course);
  }
}

class LessonRepository extends BaseRepository<Lesson> {
  constructor() {
    super('lessons');
  }

  async createWithNumber(data: Omit<Lesson, keyof BaseEntity | 'lessonNumber'>): Promise<Lesson> {
    const courseRepo = new CourseRepository();
    const course = await courseRepo.findById(data.courseId);
    if (!course) throw new Error('Course not found');

    const nextNumber = (course.totalLessons || 0) + 1;
    const lesson = await this.create({
      ...data,
      lessonNumber: nextNumber,
    } as any);

    await courseRepo.incrementTotalLessons(data.courseId);
    return lesson;
  }

  async softDelete(id: string): Promise<boolean> {
    const lesson = await this.findById(id);
    if (!lesson) return false;

    await super.softDelete(id);
    const courseRepo = new CourseRepository();
    await courseRepo.decrementTotalLessons(lesson.courseId);
    return true;
  }

  async restore(id: string): Promise<boolean> {
    const lesson = await this.findById(id, true);
    if (!lesson) return false;

    await super.restore(id);
    const courseRepo = new CourseRepository();
    await courseRepo.incrementTotalLessons(lesson.courseId);
    return true;
  }

  async findByCourse(courseId: string): Promise<Lesson[]> {
    const snapshot = await this.getCollection()
      .where('courseId', '==', courseId)
      .get();

    return snapshot.docs.map(doc => doc.data() as Lesson);
  }
}

class CategoryRepository extends BaseRepository<Category> {
  constructor() {
    super('categories');
  }
}

class EnrollmentRepository extends BaseRepository<Enrollment> {
  constructor() {
    super('enrollments');
  }

  async findByUserAndCourse(userId: string, courseId: string): Promise<Enrollment | null> {
    const snapshot = await this.getCollection()
      .where('userId', '==', userId)
      .where('courseId', '==', courseId)
      .limit(1)
      .get();

    if (snapshot.empty) return null;
    const enrollment = snapshot.docs[0].data() as Enrollment;
    if (enrollment.deletedAt) return null;
    return enrollment;
  }

  async findByUser(userId: string): Promise<Enrollment[]> {
    const snapshot = await this.getCollection()
      .where('userId', '==', userId)
      .get();

    return snapshot.docs.map(doc => doc.data() as Enrollment);
  }
}

class SupportConversationRepository extends BaseRepository<SupportConversation> {
  constructor() {
    super('support_conversations');
  }

  async assignSupportToConversation(conversationId: string, supportId: string): Promise<boolean> {
    const result = await this.update(conversationId, {
      supportId,
      status: Status.OPEN,
    } as any);
    return !!result;
  }

  async addMessage(conversationId: string, message: Message): Promise<boolean> {
    const docRef = this.getCollection().doc(conversationId);
    await docRef.update({
      messages: admin.firestore.FieldValue.arrayUnion(message),
      updatedAt: dayjs().toISOString(),
    });
    return true;
  }

  async getMetrics(): Promise<{
    open: number;
    closed: number;
    averageMessages: number;
  }> {
    const [open, closed] = await Promise.all([
      this.getCollection().where('status', '==', Status.OPEN).get(),
      this.getCollection().where('status', '==', Status.CLOSED).get()
    ]);

    const totalMessages = [...open.docs, ...closed.docs].reduce((acc, doc) => {
      return acc + (doc.data().messages?.length || 0);
    }, 0);

    const totalConversations = open.docs.length + closed.docs.length;
    const avgMessages = totalConversations > 0 ? totalMessages / totalConversations : 0;

    return {
      open: open.docs.length,
      closed: closed.docs.length,
      averageMessages: avgMessages
    };
  }
}

class RefreshTokenRepository extends BaseRepository<RefreshToken> {
  constructor() {
    super('refresh_tokens');
  }

  async findByToken(token: string): Promise<RefreshToken | null> {
    const snapshot = await this.getCollection().where('token', '==', token).limit(1).get();
    return snapshot.empty ? null : (snapshot.docs[0].data() as RefreshToken);
  }

  async invalidateToken(token: string): Promise<boolean> {
    const tokenDoc = await this.findByToken(token);
    if (!tokenDoc) return false;
    await this.permanentDelete(tokenDoc.id);
    return true;
  }
}

class ActivityLogRepository extends BaseRepository<ActivityLog> {
  constructor() {
    super('activity_logs');
  }

  async log(
    userId: string,
    action: string,
    resourceType: string,
    resourceId: string | null = null,
    details: Record<string, any> = {}
  ): Promise<void> {
    await this.create({
      userId,
      action,
      resourceType,
      resourceId,
      details
    });
  }
}

class ExamRepository extends BaseRepository<Exam> {
  constructor() {
    super('exams');
  }

  async findByCourse(courseId: string): Promise<Exam[]> {
    const snapshot = await this.getCollection()
      .where('courseId', '==', courseId)
      .get();

    return snapshot.docs.map(doc => doc.data() as Exam);
  }

  async findByLesson(lessonId: string): Promise<Exam[]> {
    const snapshot = await this.getCollection()
      .where('lessonId', '==', lessonId)
      .get();

    return snapshot.docs.map(doc => doc.data() as Exam);
  }
}

class ExamAttemptRepository extends BaseRepository<ExamAttempt> {
  constructor() {
    super('exam_attempts');
  }

  async findByUserAndExam(userId: string, examId: string): Promise<ExamAttempt[]> {
    const snapshot = await this.getCollection()
      .where('userId', '==', userId)
      .where('examId', '==', examId)
      .get();

    return snapshot.docs.map(doc => doc.data() as ExamAttempt);
  }

  async findByUser(userId: string): Promise<ExamAttempt[]> {
    const snapshot = await this.getCollection()
      .where('userId', '==', userId)
      .get();

    return snapshot.docs.map(doc => doc.data() as ExamAttempt);
  }
}

class CertificateRepository extends BaseRepository<Certificate> {
  constructor() {
    super('certificates');
  }

  async findByUser(userId: string): Promise<Certificate[]> {
    const snapshot = await this.getCollection()
      .where('userId', '==', userId)
      .get();

    return snapshot.docs.map(doc => doc.data() as Certificate);
  }

  async findByCourse(courseId: string): Promise<Certificate[]> {
    const snapshot = await this.getCollection()
      .where('courseId', '==', courseId)
      .get();

    return snapshot.docs.map(doc => doc.data() as Certificate);
  }

  async findByVerificationCode(code: string): Promise<Certificate | null> {
    const snapshot = await this.getCollection()
      .where('verificationCode', '==', code)
      .limit(1)
      .get();

    return snapshot.empty ? null : (snapshot.docs[0].data() as Certificate);
  }
}


class RoadmapRepository extends BaseRepository<Roadmap> {
  constructor() {
    super('roadmaps');
  }

  async findByCategory(categoryId: string): Promise<Roadmap[]> {
    const snapshot = await this.getCollection()
      .where('categoryId', '==', categoryId)
      .where('isPublished', '==', true)
      .get();

    return snapshot.docs.map(doc => doc.data() as Roadmap);
  }

  async findByInstructor(instructorId: string): Promise<Roadmap[]> {
    const snapshot = await this.getCollection()
      .where('instructorId', '==', instructorId)
      .get();

    return snapshot.docs.map(doc => doc.data() as Roadmap);
  }

  async findPublished(limit = 10, cursor?: string): Promise<{ data: Roadmap[]; nextCursor: string | null }> {
    let query: admin.firestore.Query = this.getCollection()
      .where('isPublished', '==', true);

    if (cursor) {
      const cursorDoc = await this.getCollection().doc(cursor).get();
      query = query.startAfter(cursorDoc);
    }

    query = query.limit(limit);

    const snapshot = await query.get();
    const data = snapshot.docs.map(doc => doc.data() as Roadmap);
    const nextCursor = snapshot.docs.length === limit ? snapshot.docs[snapshot.docs.length - 1].id : null;

    return { data, nextCursor };
  }

  async enrollUser(roadmapId: string, userId: string): Promise<boolean> {
    const roadmap = await this.findById(roadmapId);
    if (!roadmap) return false;

    const updatedEnrollments = [...roadmap.enrolledUserIds, userId];
    return !!(await this.update(roadmapId, { enrolledUserIds: updatedEnrollments }));
  }

  async unenrollUser(roadmapId: string, userId: string): Promise<boolean> {
    const roadmap = await this.findById(roadmapId);
    if (!roadmap) return false;

    const updatedEnrollments = roadmap.enrolledUserIds.filter(id => id !== userId);
    return !!(await this.update(roadmapId, { enrolledUserIds: updatedEnrollments }));
  }
}

class ChallengeRepository extends BaseRepository<Challenge> {
  constructor() {
    super('challenges');
  }

  async findActiveChallenges(): Promise<Challenge[]> {
    const now = dayjs().toISOString();
    const snapshot = await this.getCollection()
      .where('startDate', '<=', now)
      .where('endDate', '>=', now)
      .where('status', '==', ChallengeStatus.ACTIVE)
      .get();

    return snapshot.docs.map(doc => doc.data() as Challenge);
  }

  async findUpcomingChallenges(): Promise<Challenge[]> {
    const now = dayjs().toISOString();
    const snapshot = await this.getCollection()
      .where('startDate', '>', now)
      .where('status', '==', ChallengeStatus.UPCOMING)
      .get();

    return snapshot.docs.map(doc => doc.data() as Challenge);
  }

  async findEndedChallenges(): Promise<Challenge[]> {
    const now = dayjs().toISOString();
    const snapshot = await this.getCollection()
      .where('endDate', '<', now)
      .where('status', '==', ChallengeStatus.ENDED)
      .get();

    return snapshot.docs.map(doc => doc.data() as Challenge);
  }

  async findAllChallenges(limit = 10, cursor?: string): Promise<{ data: Challenge[]; nextCursor: string | null }> {
    let query: admin.firestore.Query = this.getCollection();

    if (cursor) {
      const cursorDoc = await this.getCollection().doc(cursor).get();
      query = query.startAfter(cursorDoc);
    }

    query = query.limit(limit);

    const snapshot = await query.get();
    const data = snapshot.docs.map(doc => doc.data() as Challenge);
    const nextCursor = snapshot.docs.length === limit ? snapshot.docs[snapshot.docs.length - 1].id : null;

    return { data, nextCursor };
  }

  async addParticipant(challengeId: string, userId: string): Promise<boolean> {
    const challenge = await this.findById(challengeId);
    if (!challenge) return false;

    const updatedParticipants = [...challenge.participants, userId];
    return !!(await this.update(challengeId, { participants: updatedParticipants }));
  }

  async updateLeaderboard(challengeId: string, entry: LeaderboardEntry): Promise<boolean> {
    const challenge = await this.findById(challengeId);
    if (!challenge) return false;

    const newLeaderboard = [...challenge.leaderboard, entry]
      .sort((a, b) => b.score - a.score || a.timeSpent - b.timeSpent)
      .slice(0, 100);

    return !!(await this.update(challengeId, { leaderboard: newLeaderboard }));
  }
}
class LearningProfileRepository extends BaseRepository<LearningProfile> {
  constructor() {
    super('learning_profiles');
  }

  async findByUser(userId: string): Promise<LearningProfile | null> {
    const snapshot = await this.getCollection()
      .where('userId', '==', userId)
      .limit(1)
      .get();

    return snapshot.empty ? null : (snapshot.docs[0].data() as LearningProfile);
  }
}

class RecommendationRepository extends BaseRepository<Recommendation> {
  constructor() {
    super('recommendations');
  }

  async findByUser(userId: string): Promise<Recommendation[]> {
    const snapshot = await this.getCollection()
      .where('userId', '==', userId)
      .orderBy('confidenceScore', 'desc')
      .get();

    return snapshot.docs.map(doc => doc.data() as Recommendation);
  }
}



// Cache Service
class CacheService {
  constructor(private redisClient: Redis) {}

  // In CacheService.get method
async get<T>(key: string): Promise<T | null> {
  try {
    const data = await this.redisClient.get(key);
    if (data === 'null') return null; // Handle stringified null
    return data ? JSON.parse(data) : null;
  } catch (error) {
    logger.warn(`Redis get error: ${error}`);
    return null;
  }
}

  async set<T>(key: string, value: T, ttl: number): Promise<boolean> {
    try {
      await this.redisClient.setex(key, ttl, JSON.stringify(value));
      return true;
    } catch (error) {
      logger.warn(`Redis set error: ${error}`);
      return false;
    }
  }

  async del(key: string): Promise<boolean> {
    try {
      await this.redisClient.del(key);
      return true;
    } catch (error) {
      logger.warn(`Redis del error: ${error}`);
      return false;
    }
  }

  async delByPrefix(prefix: string): Promise<boolean> {
    try {
      const keys = await this.redisClient.keys(`${prefix}:*`);
      if (keys.length > 0) {
        await this.redisClient.del(...keys);
      }
      return true;
    } catch (error) {
      logger.warn(`Redis delByPrefix error: ${error}`);
      return false;
    }
  }
}

// Services

// Firebase Storage Service


class AuthService {
  constructor(
    private userRepo: UserRepository,
    private refreshTokenRepo: RefreshTokenRepository,
    private cacheService: CacheService,
    private activityLogRepo: ActivityLogRepository
  ) {}

  async register(
    name: string,
    email: string,
    password: string,
    phoneNumber: string,
    role: Role
  ): Promise<{ user: UserDTO; accessToken: string; refreshToken: string }> {
    const existingUser = await this.userRepo.findByEmail(email);
    if (existingUser) throw new HttpError(409, 'Email already registered');

    if (!this.validatePassword(password)) {
      throw new HttpError(400, 'Password must be at least 8 characters long with uppercase, lowercase, number, and symbol');
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const user = await this.userRepo.create({
      name,
      email,
      passwordHash,
      phoneNumber,
      dateOfBirth: dayjs().toISOString(),
      country: '',
      gender: Gender.OTHER,
      role,
      profilePictureUrl: null,
      enrolledCourseIds: [],
      isBlocked: false,
    });

    await this.activityLogRepo.log(user.id, 'register', 'user', user.id);
    return this.generateTokens(user);
  }


  async login(email: string, password: string) {
    const user = await this.userRepo.findByEmail(email);
    if (!user) throw new HttpError(401, 'Invalid credentials');
    if (user.isBlocked) throw new HttpError(403, 'User account is blocked');

    const passwordMatch = await bcrypt.compare(password, user.passwordHash);
    if (!passwordMatch) throw new HttpError(401, 'Invalid credentials');

    await this.activityLogRepo.log(user.id, 'login', 'user', user.id);
    return this.generateTokens(user);
  }


  async refreshToken(refreshToken: string): Promise<{ accessToken: string; refreshToken: string }> {
    const tokenDoc = await this.refreshTokenRepo.findByToken(refreshToken);
    if (!tokenDoc) throw new HttpError(401, 'Invalid refresh token');

    const user = await this.userRepo.findById(tokenDoc.userId);
    if (!user || user.deletedAt || user.isBlocked) throw new HttpError(401, 'User not found or blocked');

    await this.refreshTokenRepo.invalidateToken(refreshToken);
    return this.generateTokens(user);
  }

  async logout(refreshToken: string): Promise<boolean> {
    return this.refreshTokenRepo.invalidateToken(refreshToken);
  }

  private validatePassword(password: string): boolean {
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
    return passwordRegex.test(password);
  }

  private async generateTokens(user: User): Promise<{ user: UserDTO; accessToken: string; refreshToken: string }> {
    const userDTO = new UserDTO(
      user.id,
      user.name,
      user.email,
      user.phoneNumber,
      user.dateOfBirth,
      user.country,
      user.gender,
      user.role,
      user.profilePictureUrl,
      user.isBlocked,
      user.createdAt,
      user.updatedAt
    );

    const accessToken = jwt.sign({ userId: user.id, role: user.role }, JWT_SECRET, {
      expiresIn: JWT_ACCESS_EXPIRY,
    } as jwt.SignOptions);

    const refreshToken = jwt.sign({ userId: user.id }, JWT_SECRET, {
      expiresIn: JWT_REFRESH_EXPIRY,
    } as jwt.SignOptions);

    await this.refreshTokenRepo.create({
      userId: user.id,
      token: refreshToken,
      expiresAt: dayjs().add(7, 'days').toISOString(),
    });

    return { user: userDTO, accessToken, refreshToken };
  }
}

class UserService {
  constructor(
    private userRepo: UserRepository,
    private enrollmentRepo: EnrollmentRepository,
    private conversationRepo: SupportConversationRepository,
    private cacheService: CacheService,
    private activityLogRepo: ActivityLogRepository,
    private storageService: FirebaseStorageService
  ) {}

  async getUserById(id: string): Promise<UserDTO> {
    try {
      if (!id || typeof id !== 'string') {
        throw new HttpError(400, 'Invalid user ID');
      }

      const cacheKey = `user:${id}`;
      const cached = await this.cacheService.get<UserDTO>(cacheKey);
      if (cached) {
        logger.debug(`Retrieved user ${id} from cache`);
        return cached;
      }

      const user = await this.userRepo.findById(id);
      if (!user) {
        logger.warn(`User not found: ${id}`);
        throw new HttpError(404, 'User not found');
      }

      if (!user.id || !user.name || !user.email || !user.role) {
        logger.error(`Invalid user data for ID: ${id}`, user);
        throw new HttpError(500, 'Invalid user data');
      }

      const userDTO = new UserDTO(
        user.id,
        user.name,
        user.email,
        user.phoneNumber || '',
        user.dateOfBirth || dayjs().toISOString(),
        user.country || '',
        user.gender || Gender.OTHER,
        user.role,
        user.profilePictureUrl || null,
        user.isBlocked || false,
        user.createdAt,
        user.updatedAt,
        user.assignedHrId || null
      );

      try {
        await this.cacheService.set(cacheKey, userDTO, REDIS_TTL_SINGLE);
        logger.debug(`Cached user data for ID: ${id}`);
      } catch (cacheError) {
        logger.warn(`Failed to cache user data for ID: ${id}`, cacheError);
      }

      return userDTO;
    } catch (error) {
      if (error instanceof HttpError) {
        throw error;
      }
      logger.error(`Error retrieving user ${id}:`, error);
      throw new HttpError(500, 'Failed to retrieve user');
    }
  }

  async updateUser(id: string, updateData: Partial<User> & { password?: string }): Promise<UserDTO> {
    const user = await this.userRepo.findById(id);
    if (!user) throw new HttpError(404, 'User not found');

    if (updateData.profilePictureUrl && user.profilePictureUrl) {
      await this.storageService.deleteFile(user.profilePictureUrl);
    }

    if (updateData.email && updateData.email !== user.email) {
      const existing = await this.userRepo.findByEmail(updateData.email);
      if (existing) throw new HttpError(409, 'Email already in use');
    }

    if (updateData.password) {
      if (!this.validatePassword(updateData.password)) {
        throw new HttpError(400, 'Password must be at least 8 characters long with uppercase, lowercase, number, and symbol');
      }
      updateData.passwordHash = await bcrypt.hash(updateData.password, 10);
      delete updateData.password;
    }

    const updated = await this.userRepo.update(id, updateData);
    if (!updated) throw new HttpError(500, 'Update failed');

    await this.cacheService.del(`user:${id}`);
    await this.cacheService.delByPrefix('users:list');
    await this.activityLogRepo.log(id, 'update_profile', 'user', id);
    return this.getUserById(id);
  }

  async getUsers(role?: Role, limit = 100, cursor?: string): Promise<UserDTO[]> {
    const filters: Record<string, any> = {};
    if (role) {
      filters.role = role;
    }

    const { data } = await this.userRepo.findMany(filters, false, limit, cursor);
    return data.map(user => new UserDTO(
      user.id,
      user.name,
      user.email,
      user.phoneNumber,
      user.dateOfBirth,
      user.country,
      user.gender,
      user.role,
      user.profilePictureUrl,
      user.isBlocked,
      user.createdAt,
      user.updatedAt,
      user.assignedHrId
    ));
  }

  async blockUser(id: string): Promise<boolean> {
    const result = await this.userRepo.blockUser(id);
    if (!result) throw new HttpError(404, 'User not found');
    await this.cacheService.del(`user:${id}`);
    await this.activityLogRepo.log(id, 'block_user', 'user', id);
    return result;
  }

  async unblockUser(id: string): Promise<boolean> {
    const result = await this.userRepo.unblockUser(id);
    if (!result) throw new HttpError(404, 'User not found');
    await this.cacheService.del(`user:${id}`);
    await this.activityLogRepo.log(id, 'unblock_user', 'user', id);
    return result;
  }

  async softDeleteUser(id: string): Promise<boolean> {
    const user = await this.userRepo.findById(id);
    if (!user) throw new HttpError(404, 'User not found');

    if (user.profilePictureUrl) {
      await this.storageService.deleteFile(user.profilePictureUrl);
    }

    const result = await this.userRepo.softDelete(id);
    if (!result) throw new HttpError(404, 'User not found');

    const [enrollments, conversations] = await Promise.all([
      this.enrollmentRepo.findMany({ userId: id }),
      this.conversationRepo.findMany({ userId: id })
    ]);

    await Promise.all([
      ...enrollments.data.map(e => this.enrollmentRepo.softDelete(e.id)),
      ...conversations.data.map(c => this.conversationRepo.softDelete(c.id))
    ]);

    await this.cacheService.del(`user:${id}`);
    await this.cacheService.delByPrefix('users:list');
    await this.activityLogRepo.log(id, 'soft_delete_user', 'user', id);
    return result;
  }

  async restoreUser(id: string): Promise<boolean> {
    const result = await this.userRepo.restore(id);
    if (!result) throw new HttpError(404, 'User not found');
    await this.cacheService.del(`user:${id}`);
    await this.cacheService.delByPrefix('users:list');
    await this.activityLogRepo.log(id, 'restore_user', 'user', id);
    return result;
  }

  private validatePassword(password: string): boolean {
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
    return passwordRegex.test(password);
  }
}

class CourseService {
  constructor(
    private courseRepo: CourseRepository,
    private lessonRepo: LessonRepository,
    private categoryRepo: CategoryRepository,
    private cacheService: CacheService,
    private activityLogRepo: ActivityLogRepository,
    private userRepo: UserRepository,
    private storageService: FirebaseStorageService
  ) {}

  async getCoursesPublic(limit = 100, cursor?: string): Promise<{ data: CourseDTO[]; nextCursor: string | null }> {
    const { data, nextCursor } = await this.courseRepo.findMany({}, false, limit, cursor);
    const dtos = data.map(c => this.mapToDTO(c));
    return { data: dtos, nextCursor };
  }

  async createCourse(data: Omit<Course, keyof BaseEntity>): Promise<CourseDTO> {
    const instructor = await this.userRepo.findById(data.instructorId);
    if (!instructor || instructor.role !== Role.INSTRUCTOR) {
      throw new HttpError(400, 'Invalid instructor');
    }

    const category = await this.categoryRepo.findById(data.categoryId);
    if (!category) throw new HttpError(400, 'Invalid category');

    const courseData = {
      ...data,
      studentIds: data.studentIds || [],
      tags: data.tags || [],
    };

    const course = await this.courseRepo.create(courseData);
    await this.activityLogRepo.log(data.instructorId, 'create_course', 'course', course.id);
    return this.mapToDTO(course);
  }

  async getCourseById(id: string): Promise<CourseDTO> {
    const cacheKey = `course:${id}`;
    const cached = await this.cacheService.get<CourseDTO>(cacheKey);
    if (cached) return cached;

    const course = await this.courseRepo.findById(id);
    if (!course) throw new HttpError(404, 'Course not found');

    const dto = this.mapToDTO(course);
    await this.cacheService.set(cacheKey, dto, REDIS_TTL_SINGLE);
    return dto;
  }

  async updateCourse(id: string, data: Partial<Course>): Promise<CourseDTO> {
    if (data.thumbnailUrl) {
      const existingCourse = await this.courseRepo.findById(id);
      if (existingCourse && existingCourse.thumbnailUrl) {
        await this.storageService.deleteFile(existingCourse.thumbnailUrl);
      }
    }

    if (data.instructorId) {
      const instructor = await this.userRepo.findById(data.instructorId);
      if (!instructor || instructor.role !== Role.INSTRUCTOR) {
        throw new HttpError(400, 'Invalid instructor');
      }
    }

    if (data.categoryId) {
      const category = await this.categoryRepo.findById(data.categoryId);
      if (!category) throw new HttpError(400, 'Invalid category');
    }

    const updated = await this.courseRepo.update(id, data);
    if (!updated) throw new HttpError(404, 'Course not found');

    await this.cacheService.del(`course:${id}`);
    await this.cacheService.delByPrefix('courses:list');
    await this.activityLogRepo.log(updated.instructorId, 'update_course', 'course', id);
    return this.mapToDTO(updated);
  }

  async softDeleteCourse(id: string): Promise<boolean> {
    const course = await this.courseRepo.findById(id);
    if (!course) throw new HttpError(404, 'Course not found');

    if (course.thumbnailUrl) {
      await this.storageService.deleteFile(course.thumbnailUrl);
    }

    const result = await this.courseRepo.softDelete(id);
    if (!result) throw new HttpError(404, 'Course not found');

    const lessons = await this.lessonRepo.findMany({ courseId: id });
    await Promise.all(lessons.data.map(lesson => this.lessonRepo.softDelete(lesson.id)));

    await this.cacheService.del(`course:${id}`);
    await this.cacheService.delByPrefix('courses:list');
    await this.activityLogRepo.log('system', 'soft_delete_course', 'course', id);
    return result;
  }

  async restoreCourse(id: string): Promise<boolean> {
    const result = await this.courseRepo.restore(id);
    if (!result) throw new HttpError(404, 'Course not found');

    const lessons = await this.lessonRepo.findMany({ courseId: id }, true);
    await Promise.all(lessons.data.map(lesson => this.lessonRepo.restore(lesson.id)));

    await this.cacheService.del(`course:${id}`);
    await this.cacheService.delByPrefix('courses:list');
    await this.activityLogRepo.log('system', 'restore_course', 'course', id);
    return result;
  }

  async getTopCourses(limit = 5): Promise<CourseDTO[]> {
    const cacheKey = `courses:top:${limit}`;
    const cached = await this.cacheService.get<CourseDTO[]>(cacheKey);
    if (cached) return cached;

    const courses = await this.courseRepo.getTopCourses(limit);
    const dtos = courses.map(c => this.mapToDTO(c));
    await this.cacheService.set(cacheKey, dtos, REDIS_TTL_LIST);
    return dtos;
  }

  private mapToDTO(course: Course): CourseDTO {
    return new CourseDTO(
      course.id,
      course.title,
      course.description,
      course.thumbnailUrl,
      course.instructorId,
      course.totalLessons,
      course.categoryId,
      course.language,
      course.level,
      course.tags,
      course.studentIds,
      course.firstPublishDate,
      course.createdAt,
      course.updatedAt
    );
  }
}

class LessonService {
  constructor(
    private lessonRepo: LessonRepository,
    private courseRepo: CourseRepository,
    private cacheService: CacheService,
    private activityLogRepo: ActivityLogRepository,
    private userRepo: UserRepository
  ) {}

  async createLesson(data: Omit<Lesson, keyof BaseEntity | 'lessonNumber'>): Promise<LessonDTO> {
  const course = await this.courseRepo.findById(data.courseId);
  if (!course) throw new HttpError(404, 'Course not found');

  const instructor = await this.userRepo.findById(data.instructorId);
  if (!instructor || instructor.role !== Role.INSTRUCTOR) {
    throw new HttpError(400, 'Invalid instructor');
  }

  // Ensure attachments is always an array
  const attachments = data.attachments || [];

  const lesson = await this.lessonRepo.createWithNumber({
    ...data,
    attachments, // Use the sanitized array
  });

  await this.activityLogRepo.log(data.instructorId, 'create_lesson', 'lesson', lesson.id, {
    courseId: data.courseId
  });

  return this.mapToDTO(lesson);
}

  async getLessonById(id: string): Promise<LessonDTO> {
    const cacheKey = `lesson:${id}`;
    const cached = await this.cacheService.get<LessonDTO>(cacheKey);
    if (cached) return cached;

    const lesson = await this.lessonRepo.findById(id);
    if (!lesson) throw new HttpError(404, 'Lesson not found');

    const dto = this.mapToDTO(lesson);
    await this.cacheService.set(cacheKey, dto, REDIS_TTL_SINGLE);
    return dto;
  }

  async updateLesson(id: string, data: Partial<Lesson>): Promise<LessonDTO> {
    if (data.instructorId) {
      const instructor = await this.userRepo.findById(data.instructorId);
      if (!instructor || instructor.role !== Role.INSTRUCTOR) {
        throw new HttpError(400, 'Invalid instructor');
      }
    }

    const updated = await this.lessonRepo.update(id, data);
    if (!updated) throw new HttpError(404, 'Lesson not found');

    await this.cacheService.del(`lesson:${id}`);
    await this.cacheService.delByPrefix(`lessons:course:${updated.courseId}`);
    await this.activityLogRepo.log(updated.instructorId, 'update_lesson', 'lesson', id);
    return this.mapToDTO(updated);
  }

  async softDeleteLesson(id: string): Promise<boolean> {
    const result = await this.lessonRepo.softDelete(id);
    if (!result) throw new HttpError(404, 'Lesson not found');

    await this.cacheService.del(`lesson:${id}`);
    await this.activityLogRepo.log('system', 'soft_delete_lesson', 'lesson', id);
    return result;
  }

  async restoreLesson(id: string): Promise<boolean> {
    const result = await this.lessonRepo.restore(id);
    if (!result) throw new HttpError(404, 'Lesson not found');

    await this.cacheService.del(`lesson:${id}`);
    await this.activityLogRepo.log('system', 'restore_lesson', 'lesson', id);
    return result;
  }

  async permanentDeleteLesson(id: string): Promise<boolean> {
    const result = await this.lessonRepo.permanentDelete(id);
    if (!result) throw new HttpError(404, 'Lesson not found');

    await this.cacheService.del(`lesson:${id}`);
    await this.activityLogRepo.log('system', 'permanent_delete_lesson', 'lesson', id);
    return result;
  }

  async getLessonsByCourse(courseId: string, limit = 10, cursor?: string): Promise<{ data: LessonDTO[]; nextCursor: string | null }> {
    const cacheKey = `lessons:course:${courseId}:${limit}:${cursor || '0'}`;
    const cached = await this.cacheService.get<{ data: LessonDTO[]; nextCursor: string | null }>(cacheKey);
    if (cached) return cached;

    const { data, nextCursor } = await this.lessonRepo.findMany({ courseId }, false, limit, cursor);
    const dtos = data.map(l => this.mapToDTO(l));
    const result = { data: dtos, nextCursor };

    await this.cacheService.set(cacheKey, result, REDIS_TTL_LIST);
    return result;
  }

  private mapToDTO(lesson: Lesson): LessonDTO {
    return new LessonDTO(
      lesson.id,
      lesson.courseId,
      lesson.lessonNumber,
      lesson.title,
      lesson.description,
      lesson.videoUrl,
      lesson.attachments,
      lesson.thumbnailUrl,
      lesson.instructorId,
      lesson.durationMinutes,
      lesson.createdAt,
      lesson.updatedAt
    );
  }
}

class CategoryService {
  constructor(
    private categoryRepo: CategoryRepository,
    private cacheService: CacheService,
    private activityLogRepo: ActivityLogRepository
  ) {}

  async createCategory(name: string, description: string): Promise<CategoryDTO> {
    const category = await this.categoryRepo.create({ name, description });
    await this.activityLogRepo.log('system', 'create_category', 'category', category.id);
    return this.mapToDTO(category);
  }

  async getCategoryById(id: string): Promise<CategoryDTO> {
    const cacheKey = `category:${id}`;
    const cached = await this.cacheService.get<CategoryDTO>(cacheKey);
    if (cached) return cached;

    const category = await this.categoryRepo.findById(id);
    if (!category) throw new HttpError(404, 'Category not found');

    const dto = this.mapToDTO(category);
    await this.cacheService.set(cacheKey, dto, REDIS_TTL_SINGLE);
    return dto;
  }

  async updateCategory(id: string, data: Partial<Category>): Promise<CategoryDTO> {
    const updated = await this.categoryRepo.update(id, data);
    if (!updated) throw new HttpError(404, 'Category not found');

    await this.cacheService.del(`category:${id}`);
    await this.cacheService.delByPrefix('categories:list');
    await this.activityLogRepo.log('system', 'update_category', 'category', id);
    return this.mapToDTO(updated);
  }

  async softDeleteCategory(id: string): Promise<boolean> {
    const result = await this.categoryRepo.softDelete(id);
    if (!result) throw new HttpError(404, 'Category not found');

    await this.cacheService.del(`category:${id}`);
    await this.cacheService.delByPrefix('categories:list');
    await this.activityLogRepo.log('system', 'soft_delete_category', 'category', id);
    return result;
  }

  async restoreCategory(id: string): Promise<boolean> {
    const result = await this.categoryRepo.restore(id);
    if (!result) throw new HttpError(404, 'Category not found');

    await this.cacheService.del(`category:${id}`);
    await this.cacheService.delByPrefix('categories:list');
    await this.activityLogRepo.log('system', 'restore_category', 'category', id);
    return result;
  }

  async permanentDeleteCategory(id: string): Promise<boolean> {
    const result = await this.categoryRepo.permanentDelete(id);
    if (!result) throw new HttpError(404, 'Category not found');

    await this.cacheService.del(`category:${id}`);
    await this.cacheService.delByPrefix('categories:list');
    await this.activityLogRepo.log('system', 'permanent_delete_category', 'category', id);
    return result;
  }

  private mapToDTO(category: Category): CategoryDTO {
    return new CategoryDTO(
      category.id,
      category.name,
      category.description,
      category.createdAt,
      category.updatedAt
    );
  }
}

class EnrollmentService {
  constructor(
    private enrollmentRepo: EnrollmentRepository,
    private userRepo: UserRepository,
    private courseRepo: CourseRepository,
    private cacheService: CacheService,
    private activityLogRepo: ActivityLogRepository
  ) {}

    async enrollStudent(userId: string, courseId: string): Promise<Enrollment> {
  try {
    const user = await this.userRepo.findById(userId);
    if (!user || user.role !== Role.STUDENT) {
      throw new HttpError(400, 'Invalid student');
    }

    const course = await this.courseRepo.findById(courseId);
    if (!course) {
      throw new HttpError(404, 'Course not found');
    }

    // Check if user is already enrolled
    const existingEnrollment = await this.enrollmentRepo.findByUserAndCourse(userId, courseId);
    if (existingEnrollment) {
      throw new HttpError(409, 'Already enrolled in this course');
    }

    const enrollment = await this.enrollmentRepo.create({
      userId,
      courseId,
      lessonsCompleted: [],
      rating: null,
      completedAt: null,
    });

    // Update user's enrolled courses - handle undefined array
    await this.userRepo.update(userId, {
      enrolledCourseIds: [...(user.enrolledCourseIds || []), courseId],
    });

    // Update course's student count - handle undefined array
    await this.courseRepo.update(courseId, {
      studentIds: [...(course.studentIds || []), userId],
    });

    await this.cacheService.del(`user:${userId}`);
    await this.cacheService.del(`course:${courseId}`);

    return enrollment;
  } catch (error) {
    logger.error('Enrollment error:', error);
    throw new HttpError(500, 'Failed to enroll student');
  }
}



  async updateProgress(
    enrollmentId: string,
    lessonId: string,
    rating?: number
  ): Promise<{ enrollment: Enrollment; completed: boolean }> {
    const enrollment = await this.enrollmentRepo.findById(enrollmentId);
    if (!enrollment) throw new HttpError(404, 'Enrollment not found');

    const updatedLessons = [...new Set([...enrollment.lessonsCompleted, lessonId])];
    const isCompleted = updatedLessons.length >= (await this.getTotalLessons(enrollment.courseId));

    const updateData: Partial<Enrollment> = {
      lessonsCompleted: updatedLessons,
    };

    if (isCompleted) {
      updateData.completedAt = dayjs().toISOString();
      updateData.rating = rating ?? enrollment.rating;
    }

    const updated = await this.enrollmentRepo.update(enrollmentId, updateData);
    if (!updated) throw new HttpError(500, 'Update failed');

    await this.activityLogRepo.log(
      enrollment.userId,
      'update_progress',
      'enrollment',
      enrollmentId,
      { lessonId, completed: isCompleted }
    );
    return { enrollment: updated, completed: isCompleted };
  }

  private async getTotalLessons(courseId: string): Promise<number> {
    const course = await this.courseRepo.findById(courseId);
    return course?.totalLessons || 0;
  }
}

class SupportService {
  constructor(
    private conversationRepo: SupportConversationRepository,
    private userRepo: UserRepository,
    private cacheService: CacheService,
    private activityLogRepo: ActivityLogRepository
  ) {}

  async createConversation(userId: string): Promise<SupportConversation> {
    const user = await this.userRepo.findById(userId);
    if (!user) throw new HttpError(404, 'User not found');

    // Round-robin assignment
    const supportStaff = await this.userRepo.findMany({ role: Role.SUPPORT }, false, 100);
    if (supportStaff.data.length === 0) throw new HttpError(503, 'No support staff available');

    const lastAssignedIndex = await this.getLastAssignedIndex();
    const nextIndex = (lastAssignedIndex + 1) % supportStaff.data.length;
    const supportId = supportStaff.data[nextIndex]?.id || null;

    await this.setLastAssignedIndex(nextIndex);

    const conversation = await this.conversationRepo.create({
      userId,
      supportId,
      status: Status.OPEN,
      messages: [],
    });

    await this.activityLogRepo.log(userId, 'create_support_conversation', 'support', conversation.id);
    return conversation;
  }

  async addMessage(conversationId: string, senderId: string, content: string): Promise<Message> {
    const conversation = await this.conversationRepo.findById(conversationId);
    if (!conversation) throw new HttpError(404, 'Conversation not found');

    // First responder becomes permanent owner
    if (!conversation.supportId && (await this.isSupportStaff(senderId))) {
      await this.conversationRepo.assignSupportToConversation(conversationId, senderId);
      conversation.supportId = senderId;
    }

    const message: Message = {
      id: uuidv4(),
      senderId,
      content,
      timestamp: dayjs().toISOString(),
      read: false,
    };

    await this.conversationRepo.addMessage(conversationId, message);
    await this.activityLogRepo.log(senderId, 'add_support_message', 'support', conversationId);
    return message;
  }

  async getMetrics() {
    return this.conversationRepo.getMetrics();
  }

  private async getLastAssignedIndex(): Promise<number> {
    const index = await redisClient.get('support:lastAssignedIndex');
    return index ? parseInt(index) : -1;
  }

  private async setLastAssignedIndex(index: number): Promise<void> {
    await redisClient.set('support:lastAssignedIndex', index.toString());
  }

  private async isSupportStaff(userId: string): Promise<boolean> {
    const user = await this.userRepo.findById(userId);
    return !!user && user.role === Role.SUPPORT;
  }
}

class ReportService {
  constructor(
    private userRepo: UserRepository,
    private enrollmentRepo: EnrollmentRepository,
    private conversationRepo: SupportConversationRepository,
    private lessonRepo: LessonRepository,
    private storageService: FirebaseStorageService
  ) {}

  async generateUserReport(userId: string): Promise<UserReport> {
    const user = await this.userRepo.findById(userId);
    if (!user) throw new HttpError(404, 'User not found');

    const [enrollments, conversations] = await Promise.all([
      this.enrollmentRepo.findByUser(userId),
      this.conversationRepo.findMany({ userId })
    ]);

    let totalLessons = 0;
    let completedLessons = 0;
    let completedCourses = 0;

    for (const enrollment of enrollments) {
      const courseLessons = await this.lessonRepo.findByCourse(enrollment.courseId);
      totalLessons += courseLessons.length;
      completedLessons += enrollment.lessonsCompleted.length;
      if (enrollment.completedAt) completedCourses++;
    }

    const userDTO = new UserDTO(
      user.id,
      user.name,
      user.email,
      user.phoneNumber,
      user.dateOfBirth,
      user.country,
      user.gender,
      user.role,
      user.profilePictureUrl,
      user.isBlocked,
      user.createdAt,
      user.updatedAt
    );

    return {
      user: userDTO,
      enrollments: enrollments.map(e => new EnrollmentDTO(
        e.id,
        e.userId,
        e.courseId,
        e.lessonsCompleted,
        e.rating,
        e.completedAt,
        e.createdAt,
        e.updatedAt
      )),
      progress: {
        totalCourses: enrollments.length,
        completedCourses,
        totalLessons,
        completedLessons
      },
      supportConversations: conversations.data.map(c => new SupportConversationDTO(
        c.id,
        c.userId,
        c.supportId,
        c.status,
        c.messages,
        c.createdAt,
        c.updatedAt
      ))
    };
  }

  async exportReport(report: UserReport, format: ExportFormat): Promise<string> {
    const fileName = `user-report-${report.user.id}-${Date.now()}.${format}`;
    const tempFilePath = path.join('/tmp', fileName);

    if (format === ExportFormat.CSV) {
      const csvWriter = csv.createObjectCsvWriter({
        path: tempFilePath,
        header: [
          { id: 'id', title: 'ID' },
          { id: 'name', title: 'Name' },
          { id: 'email', title: 'Email' },
          { id: 'totalCourses', title: 'Total Courses' },
          { id: 'completedCourses', title: 'Completed Courses' },
          { id: 'totalLessons', title: 'Total Lessons' },
          { id: 'completedLessons', title: 'Completed Lessons' }
        ]
      });

      await csvWriter.writeRecords([{
        id: report.user.id,
        name: report.user.name,
        email: report.user.email,
        totalCourses: report.progress.totalCourses,
        completedCourses: report.progress.completedCourses,
        totalLessons: report.progress.totalLessons,
        completedLessons: report.progress.completedLessons
      }]);
    } else if (format === ExportFormat.PDF) {
      await new Promise<void>((resolve, reject) => {
        const doc = new PDFDocument();
        const stream = fs.createWriteStream(tempFilePath);
        doc.pipe(stream);

        doc.fontSize(20).text('User Report', { align: 'center' });
        doc.moveDown();

        doc.fontSize(14).text(`Name: ${report.user.name}`);
        doc.text(`Email: ${report.user.email}`);
        doc.text(`Total Courses: ${report.progress.totalCourses}`);
        doc.text(`Completed Courses: ${report.progress.completedCourses}`);
        doc.text(`Total Lessons: ${report.progress.totalLessons}`);
        doc.text(`Completed Lessons: ${report.progress.completedLessons}`);

        doc.end();

        stream.on('finish', () => resolve());
        stream.on('error', reject);
      });
    }

    // Upload to Firebase Storage
    const fileUrl = await this.storageService.uploadFromPath(tempFilePath, 'reports');
    
    // Clean up temporary file
    fs.unlinkSync(tempFilePath);
    
    return fileUrl;
  }
}

class AdminService {
  constructor(
    private userRepo: UserRepository,
    private courseRepo: CourseRepository,
    private lessonRepo: LessonRepository,
    private categoryRepo: CategoryRepository,
    private enrollmentRepo: EnrollmentRepository,
    private conversationRepo: SupportConversationRepository,
    private supportService: SupportService
  ) {}

  async getDashboard(): Promise<AdminDashboard> {
    const [
      blockedUsers,
      deletedUsers,
      deletedCourses,
      deletedLessons,
      deletedCategories,
      deletedEnrollments,
      deletedConversations,
      supportMetrics,
      totalCourses,
      topCourses
    ] = await Promise.all([
      this.userRepo.findMany({ isBlocked: true }).then(res => res.data.length),
      this.userRepo.findMany({}, true).then(res => res.data.filter(u => u.deletedAt).length),
      this.courseRepo.findMany({}, true).then(res => res.data.filter(c => c.deletedAt).length),
      this.lessonRepo.findMany({}, true).then(res => res.data.filter(l => l.deletedAt).length),
      this.categoryRepo.findMany({}, true).then(res => res.data.filter(c => c.deletedAt).length),
      this.enrollmentRepo.findMany({}, true).then(res => res.data.filter(e => e.deletedAt).length),
      this.conversationRepo.findMany({}, true).then(res => res.data.filter(c => c.deletedAt).length),
      this.supportService.getMetrics(),
      this.courseRepo.findMany().then(res => res.data.length),
      this.courseRepo.getTopCourses(5)
    ]);

    const courseAggregates = {
      totalCourses,
      averageStudents: totalCourses > 0 ? 
        topCourses.reduce((sum, course) => sum + course.studentIds.length, 0) / totalCourses : 0,
      topCourses: topCourses.map(c => new CourseDTO(
        c.id,
        c.title,
        c.description,
        c.thumbnailUrl,
        c.instructorId,
        c.totalLessons,
        c.categoryId,
        c.language,
        c.level,
        c.tags,
        c.studentIds,
        c.firstPublishDate,
        c.createdAt,
        c.updatedAt
      ))
    };

    return {
      blockedUsers,
      deletedItems: {
        users: deletedUsers,
        courses: deletedCourses,
        lessons: deletedLessons,
        categories: deletedCategories,
        enrollments: deletedEnrollments,
        conversations: deletedConversations
      },
      supportMetrics: {
        openConversations: supportMetrics.open,
        closedConversations: supportMetrics.closed,
        averageMessages: supportMetrics.averageMessages
      },
      courseAggregates
    };
  }
}

class HrService {
  constructor(
    private userRepo: UserRepository
  ) {}

  async getInstructors(): Promise<UserDTO[]> {
    const instructors = await this.userRepo.findMany({ role: Role.INSTRUCTOR }, false, 1000);
    return instructors.data.map(i => new UserDTO(
      i.id,
      i.name,
      i.email,
      i.phoneNumber,
      i.dateOfBirth,
      i.country,
      i.gender,
      i.role,
      i.profilePictureUrl,
      i.isBlocked,
      i.createdAt,
      i.updatedAt,
      i.assignedHrId
    ));
  }

  async assignInstructor(instructorId: string, hrId: string): Promise<boolean> {
    const instructor = await this.userRepo.findById(instructorId);
    if (!instructor || instructor.role !== Role.INSTRUCTOR) {
      throw new HttpError(404, 'Instructor not found');
    }

    const hr = await this.userRepo.findById(hrId);
    if (!hr || hr.role !== Role.HR) {
      throw new HttpError(404, 'HR member not found');
    }

    return this.userRepo.assignHr(instructorId, hrId);
  }
}

class BinService {
  constructor(
    private userRepo: UserRepository,
    private courseRepo: CourseRepository,
    private lessonRepo: LessonRepository,
    private categoryRepo: CategoryRepository,
    private enrollmentRepo: EnrollmentRepository,
    private conversationRepo: SupportConversationRepository
  ) {}

  async getDeletedItems(): Promise<{
    users: User[];
    courses: Course[];
    lessons: Lesson[];
    categories: Category[];
    enrollments: Enrollment[];
    conversations: SupportConversation[];
  }> {
    const [
      users,
      courses,
      lessons,
      categories,
      enrollments,
      conversations,
    ] = await Promise.all([
      this.userRepo.findMany({}, true, 100).then(res => res.data.filter(u => u.deletedAt)),
      this.courseRepo.findMany({}, true, 100).then(res => res.data.filter(c => c.deletedAt)),
      this.lessonRepo.findMany({}, true, 100).then(res => res.data.filter(l => l.deletedAt)),
      this.categoryRepo.findMany({}, true, 100).then(res => res.data.filter(c => c.deletedAt)),
      this.enrollmentRepo.findMany({}, true, 100).then(res => res.data.filter(e => e.deletedAt)),
      this.conversationRepo.findMany({}, true, 100).then(res => res.data.filter(c => c.deletedAt)),
    ]);

    return { users, courses, lessons, categories, enrollments, conversations };
  }
}

class SnapshotService {
  constructor() {}

  async exportSnapshot(): Promise<string> {
    const collections = [
      'users', 'courses', 'lessons', 'categories', 
      'enrollments', 'support_conversations', 'refresh_tokens'
    ];

    const timestamp = dayjs().format('YYYYMMDD-HHmmss');
    const snapshotDir = path.join('/tmp', `snapshot-${timestamp}`);
    if (!fs.existsSync(snapshotDir)) fs.mkdirSync(snapshotDir, { recursive: true });

    for (const collection of collections) {
      const fullCollection = `${firestorePrefix}_${collection}`;
      const snapshot = await db.collection(fullCollection).get();
      const data = snapshot.docs.map(doc => doc.data());

      const filePath = path.join(snapshotDir, `${collection}.json`);
      fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
    }

    return snapshotDir;
  }

  async restoreSnapshot(dirPath: string): Promise<void> {
    if (!fs.existsSync(dirPath)) throw new HttpError(400, 'Snapshot directory not found');

    const collections = [
      'users', 'courses', 'lessons', 'categories', 
      'enrollments', 'support_conversations', 'refresh_tokens'
    ];

    for (const collection of collections) {
      const filePath = path.join(dirPath, `${collection}.json`);
      if (!fs.existsSync(filePath)) continue;

      const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
      const collectionRef = db.collection(`${firestorePrefix}_${collection}`);

      const batch = db.batch();
      data.forEach((doc: any) => {
        const docRef = collectionRef.doc(doc.id);
        batch.set(docRef, doc);
      });
      await batch.commit();
    }
  }
}

class RoadmapService {
  constructor(
    private roadmapRepo: RoadmapRepository,
    private courseRepo: CourseRepository,
    private userRepo: UserRepository,
    private cacheService: CacheService,
    private activityLogRepo: ActivityLogRepository
  ) {}

  async createRoadmap(data: Omit<Roadmap, keyof BaseEntity>): Promise<RoadmapDTO> {
    for (const courseId of data.courseIds) {
      const course = await this.courseRepo.findById(courseId);
      if (!course) throw new HttpError(400, `Course ${courseId} not found`);
    }

    const roadmap = await this.roadmapRepo.create(data);
    await this.activityLogRepo.log(data.instructorId, 'create_roadmap', 'roadmap', roadmap.id);
    return this.mapToDTO(roadmap);
  }

  async getRoadmapById(id: string, userId?: string): Promise<RoadmapDTO> {
    const cacheKey = `roadmap:${id}${userId ? `:${userId}` : ''}`;
    const cached = await this.cacheService.get<RoadmapDTO>(cacheKey);
    if (cached) return cached;

    const roadmap = await this.roadmapRepo.findById(id);
    if (!roadmap) throw new HttpError(404, 'Roadmap not found');

    let progress;
    if (userId && roadmap.enrolledUserIds.includes(userId)) {
      const user = await this.userRepo.findById(userId);
      const completedCourses = user?.enrolledCourseIds.filter(courseId => 
        roadmap.courseIds.includes(courseId)
      ).length || 0;

      progress = {
        completedCourses,
        totalCourses: roadmap.courseIds.length,
        percentage: Math.round((completedCourses / roadmap.courseIds.length) * 100)
      };
    }

    const dto = this.mapToDTO(roadmap, progress);
    await this.cacheService.set(cacheKey, dto, REDIS_TTL_SINGLE);
    return dto;
  }

  async getRoadmaps(limit = 10, cursor?: string): Promise<{ data: RoadmapDTO[]; nextCursor: string | null }> {
    const cacheKey = `roadmaps:${limit}:${cursor || '0'}`;
    const cached = await this.cacheService.get<{ data: RoadmapDTO[]; nextCursor: string | null }>(cacheKey);
    if (cached) return cached;

    const { data, nextCursor } = await this.roadmapRepo.findPublished(limit, cursor);
    const dtos = data.map(r => this.mapToDTO(r));
    const result = { data: dtos, nextCursor };

    await this.cacheService.set(cacheKey, result, REDIS_TTL_LIST);
    return result;
  }

  async enrollUser(roadmapId: string, userId: string): Promise<boolean> {
    const result = await this.roadmapRepo.enrollUser(roadmapId, userId);
    if (!result) throw new HttpError(404, 'Roadmap not found');

    await this.cacheService.del(`roadmap:${roadmapId}`);
    await this.cacheService.del(`roadmap:${roadmapId}:${userId}`);
    await this.activityLogRepo.log(userId, 'enroll_roadmap', 'roadmap', roadmapId);
    return result;
  }

  private mapToDTO(roadmap: Roadmap, progress?: any): RoadmapDTO {
    return new RoadmapDTO(
      roadmap.id,
      roadmap.title,
      roadmap.description,
      roadmap.thumbnailUrl,
      roadmap.introVideoUrl,
      roadmap.estimatedHours,
      roadmap.difficulty,
      roadmap.categoryId,
      roadmap.courseIds,
      roadmap.enrolledUserIds,
      roadmap.isPublished,
      roadmap.tags,
      roadmap.instructorId,
      roadmap.objectives,
      roadmap.prerequisites,
      progress
    );
  }
}

class ChallengeService {
  constructor(
    private challengeRepo: ChallengeRepository,
    private userRepo: UserRepository,
    private cacheService: CacheService,
    private activityLogRepo: ActivityLogRepository
  ) {}

  async createChallenge(data: Omit<Challenge, keyof BaseEntity>): Promise<Challenge> {
    const challenge = await this.challengeRepo.create(data);
    await this.activityLogRepo.log('admin', 'create_challenge', 'challenge', challenge.id);
    return challenge;
  }

  async getChallengeById(id: string, userId?: string): Promise<ChallengeDTO> {
    const cacheKey = `challenge:${id}${userId ? `:${userId}` : ''}`;
    const cached = await this.cacheService.get<ChallengeDTO>(cacheKey);
    if (cached) return cached;

    const challenge = await this.challengeRepo.findById(id);
    if (!challenge) throw new HttpError(404, 'Challenge not found');

    let userSubmission;
    if (userId) {
      const user = await this.userRepo.findById(userId);
      if (user && user.challengeSubmissions && user.challengeSubmissions[id]) {
        userSubmission = user.challengeSubmissions[id];

// استخدم هذا:
if (challenge.status === ChallengeStatus.ENDED) {
  const index = challenge.leaderboard?.findIndex(
    (entry: LeaderboardEntry) => entry.userId === userId
  );
  if (index !== undefined && index !== -1) {
    userSubmission = {
      ...userSubmission,
      rank: index + 1
    };
  }
}
      }
    }

    const dto = this.mapToDTO(challenge, userSubmission);
    await this.cacheService.set(cacheKey, dto, REDIS_TTL_SINGLE);
    return dto;
  }

  async getChallenges(type?: 'active' | 'upcoming' | 'ended', limit = 10, cursor?: string): Promise<{ data: ChallengeDTO[]; nextCursor: string | null }> {
    let challenges: Challenge[];
    let cacheKey: string;

    if (type) {
      cacheKey = `challenges:${type}:${limit}:${cursor || '0'}`;
      const cached = await this.cacheService.get<{ data: ChallengeDTO[]; nextCursor: string | null }>(cacheKey);
      if (cached) return cached;

      if (type === 'active') {
        challenges = await this.challengeRepo.findActiveChallenges();
      } else if (type === 'upcoming') {
        challenges = await this.challengeRepo.findUpcomingChallenges();
      } else {
        challenges = await this.challengeRepo.findEndedChallenges();
      }
      // Note: for filtered queries, we might not support pagination simply, so we return all without cursor
      const dtos = challenges.map(c => this.mapToDTO(c));
      const result = { data: dtos, nextCursor: null };
      await this.cacheService.set(cacheKey, result, REDIS_TTL_LIST);
      return result;
    } else {
      cacheKey = `challenges:all:${limit}:${cursor || '0'}`;
      const cached = await this.cacheService.get<{ data: ChallengeDTO[]; nextCursor: string | null }>(cacheKey);
      if (cached) return cached;

      const { data, nextCursor } = await this.challengeRepo.findAllChallenges(limit, cursor);
      const dtos = data.map(c => this.mapToDTO(c));
      const result = { data: dtos, nextCursor };
      await this.cacheService.set(cacheKey, result, REDIS_TTL_LIST);
      return result;
    }
  }

  async submitChallengeAnswers(
    challengeId: string, 
    userId: string, 
    answers: number[],
    timeSpent: number
  ): Promise<{ score: number; rank?: number; correctAnswers: number[] }> {
    const challenge = await this.challengeRepo.findById(challengeId);
    if (!challenge) throw new HttpError(404, 'Challenge not found');
    if (challenge.status !== ChallengeStatus.ACTIVE) {
      throw new HttpError(400, 'Challenge is not active');
    }

    let score = 0;
    const correctAnswers: number[] = [];

    challenge.questions.forEach((question, index) => {
      correctAnswers.push(question.correctAnswer);
      if (answers[index] === question.correctAnswer) {
        score += question.points;
      }
    });

    const entry: LeaderboardEntry = {
      userId,
      score,
      timeSpent,
      completedAt: dayjs().toISOString()
    };

    await this.challengeRepo.updateLeaderboard(challengeId, entry);
    await this.challengeRepo.addParticipant(challengeId, userId);

    await this.saveUserSubmission(userId, challengeId, {
      answers,
      score,
      timeSpent,
      completedAt: entry.completedAt
    });

    const updatedChallenge = await this.challengeRepo.findById(challengeId);
let rank: number | undefined = undefined;
if (updatedChallenge && updatedChallenge.leaderboard) {
  const index = updatedChallenge.leaderboard.findIndex(
    (entry: LeaderboardEntry) => entry.userId === userId
  );
  if (index !== -1) {
    rank = index + 1;
  }
}

    await this.activityLogRepo.log(userId, 'submit_challenge', 'challenge', challengeId, { score, rank });

    return { score, rank, correctAnswers };
  }

  async getLeaderboard(challengeId: string, limit = 20): Promise<LeaderboardEntry[]> {
    const challenge = await this.challengeRepo.findById(challengeId);
    if (!challenge) throw new HttpError(404, 'Challenge not found');

    const leaderboardWithUsers = await Promise.all(
      challenge.leaderboard.slice(0, limit).map(async (entry, index) => {
        const user = await this.userRepo.findById(entry.userId);
        return {
          ...entry,
          rank: index + 1,
          userName: user?.name || 'Unknown User'
        };
      })
    );

    return leaderboardWithUsers;
  }

  private async saveUserSubmission(
    userId: string, 
    challengeId: string, 
    submission: Omit<UserChallengeSubmission, 'rank'>
  ): Promise<void> {
    const user = await this.userRepo.findById(userId);
    if (!user) return;

    const challengeSubmissions = user.challengeSubmissions || {};
    challengeSubmissions[challengeId] = submission;

// Replace line 2364 with:
await this.userRepo.update(userId, { 
  challengeSubmissions: challengeSubmissions 
} as Partial<User>);

  }

  private mapToDTO(challenge: Challenge, userSubmission?: UserChallengeSubmission): ChallengeDTO {
    return new ChallengeDTO(
      challenge.id,
      challenge.title,
      challenge.description,
      challenge.type,
      challenge.status,
      challenge.startDate,
      challenge.endDate,
      challenge.questions,
      challenge.totalPoints,
      challenge.durationMinutes,
      challenge.participants.length,
      userSubmission
    );
  }
}

class ExamService {
  constructor(
    private examRepo: ExamRepository,
    private attemptRepo: ExamAttemptRepository,
    private certificateRepo: CertificateRepository,
    private userRepo: UserRepository,
    private courseRepo: CourseRepository,
    private cacheService: CacheService,
    private activityLogRepo: ActivityLogRepository,
    private storageService: FirebaseStorageService
  ) {}

  async createExam(data: Omit<Exam, keyof BaseEntity>): Promise<Exam> {
    const exam = await this.examRepo.create(data);
    await this.activityLogRepo.log('system', 'create_exam', 'exam', exam.id);
    return exam;
  }

  async getExamById(id: string): Promise<ExamDTO> {
    const cacheKey = `exam:${id}`;
    const cached = await this.cacheService.get<ExamDTO>(cacheKey);
    if (cached) return cached;

    const exam = await this.examRepo.findById(id);
    if (!exam) throw new HttpError(404, 'Exam not found');

    const dto = new ExamDTO(
      exam.id,
      exam.courseId,
      exam.lessonId || null,
      exam.title,
      exam.description,
      exam.type,
      exam.durationMinutes,
      exam.passingScore,
      exam.questions,
      exam.maxAttempts,
      exam.availableFrom || null,
      exam.availableUntil || null,
      exam.createdAt,
      exam.updatedAt
    );

    await this.cacheService.set(cacheKey, dto, REDIS_TTL_SINGLE);
    return dto;
  }

  async submitExam(
    examId: string, 
    userId: string, 
    answers: { questionId: string, answer: string | number }[],
    timeSpent: number
  ): Promise<{ score: number; passed: boolean; correctAnswers: Record<string, any> }> {
    const exam = await this.examRepo.findById(examId);
    if (!exam) throw new HttpError(404, 'Exam not found');

    // Check if exam is available
    const now = dayjs();
    if (exam.availableFrom && now.isBefore(exam.availableFrom)) {
      throw new HttpError(400, 'Exam is not available yet');
    }
    if (exam.availableUntil && now.isAfter(exam.availableUntil)) {
      throw new HttpError(400, 'Exam is no longer available');
    }

    // Check attempt limit
    const attempts = await this.attemptRepo.findByUserAndExam(userId, examId);
    if (attempts.length >= exam.maxAttempts) {
      throw new HttpError(400, 'Maximum attempts reached for this exam');
    }

    // Calculate score
    let score = 0;
    const correctAnswers: Record<string, any> = {};

    exam.questions.forEach(question => {
      const userAnswer = answers.find(a => a.questionId === question.id);
      let isCorrect = false;

      if (question.type === QuestionType.MULTIPLE_CHOICE || question.type === QuestionType.TRUE_FALSE) {
        isCorrect = userAnswer?.answer === question.correctAnswer;
      } else if (question.type === QuestionType.ESSAY) {
        // Essay questions need manual grading, so we don't auto-score them
        isCorrect = false;
      }

      if (isCorrect) {
        score += question.points;
      }

      correctAnswers[question.id] = {
        correctAnswer: question.correctAnswer,
        explanation: question.explanation
      };
    });

    const passed = score >= exam.passingScore;

    // Save attempt
    await this.attemptRepo.create({
      userId,
      examId,
      answers,
      score,
      passed,
      timeSpent
    });

    // Issue certificate if passed and it's a final exam
    if (passed && exam.type === ExamType.FINAL) {
      await this.issueCertificate(userId, exam.courseId, score);
    }

    await this.activityLogRepo.log(userId, 'submit_exam', 'exam', examId, { score, passed });

    return { score, passed, correctAnswers };
  }

  private async issueCertificate(userId: string, courseId: string, score: number): Promise<void> {
    const existing = await this.certificateRepo.findMany({ 
      userId, 
      courseId 
    });

    if (existing.data.length > 0) return; // Certificate already issued

    const grade = this.calculateGrade(score);
    const certificateUrl = await this.generateCertificate(userId, courseId, grade);
    const verificationCode = uuidv4();

    await this.certificateRepo.create({
      userId,
      courseId,
      issueDate: dayjs().toISOString(),
      certificateUrl,
      verificationCode,
      grade
    });
  }

  private calculateGrade(score: number): string {
    if (score >= 90) return 'A';
    if (score >= 80) return 'B';
    if (score >= 70) return 'C';
    if (score >= 60) return 'D';
    return 'F';
  }

  private async generateCertificate(userId: string, courseId: string, grade: string): Promise<string> {
  const pdfBuffer = await new Promise<Buffer>((resolve, reject) => {
    const doc = new PDFDocument({
      size: 'landscape',
      layout: 'landscape',
      margins: {
        top: 50,
        bottom: 50,
        left: 72,
        right: 72
      }
    });
    
    const chunks: any[] = [];
    
    doc.on('data', (chunk: any) => chunks.push(chunk));
    doc.on('end', () => resolve(Buffer.concat(chunks)));
    doc.on('error', reject);

    // Add background
    doc.rect(0, 0, doc.page.width, doc.page.height).fill('#f8f9fa');
    
    // Add border
    doc.strokeColor('#007bff').lineWidth(20);
    doc.rect(10, 10, doc.page.width - 20, doc.page.height - 20).stroke();
    
    // Add title - FIXED: Set y position first, then text
    doc.y = 150;
    doc.fontSize(36).fillColor('#343a40').text('CERTIFICATE OF COMPLETION', {
      align: 'center'
    });
    
    // Add user info - FIXED: Use moveDown instead of y positioning
    doc.moveDown(2);
    doc.fontSize(24).fillColor('#6c757d').text(`This certifies that`, {
      align: 'center'
    });
    
    doc.moveDown();
    doc.fontSize(32).fillColor('#007bff').text(userId, {
      align: 'center'
    });
    
    doc.moveDown();
    doc.fontSize(24).fillColor('#6c757d').text(`has successfully completed the course`, {
      align: 'center'
    });
    
    doc.moveDown();
    doc.fontSize(28).fillColor('#343a40').text(courseId, {
      align: 'center'
    });
    
    doc.moveDown();
    doc.fontSize(20).fillColor('#6c757d').text(`with a grade of ${grade}`, {
      align: 'center'
    });
    
    // Add date
    doc.moveDown(2);
    doc.fontSize(16).fillColor('#6c757d').text(`Issued on: ${dayjs().format('MMMM D, YYYY')}`, {
      align: 'center'
    });
    
    // Add verification info
    doc.moveDown();
    doc.fontSize(12).fillColor('#adb5bd').text(`Verification Code: ${uuidv4()}`, {
      align: 'center'
    });

    doc.end();
  });

  // Upload to Firebase Storage
  const fileName = `certificate-${userId}-${courseId}-${Date.now()}.pdf`;
  return await this.storageService.uploadFile(pdfBuffer, fileName, 'certificates');
}

  async getCertificatesByUser(userId: string): Promise<CertificateDTO[]> {
    const certificates = await this.certificateRepo.findByUser(userId);
    return certificates.map(c => new CertificateDTO(
      c.id,
      c.userId,
      c.courseId,
      c.issueDate,
      c.certificateUrl,
      c.verificationCode,
      c.grade || null,
      c.createdAt,
      c.updatedAt
    ));
  }

  async verifyCertificate(code: string): Promise<{ valid: boolean; certificate?: CertificateDTO }> {
    const certificate = await this.certificateRepo.findByVerificationCode(code);
    if (!certificate) return { valid: false };

    const dto = new CertificateDTO(
      certificate.id,
      certificate.userId,
      certificate.courseId,
      certificate.issueDate,
      certificate.certificateUrl,
      certificate.verificationCode,
      certificate.grade || null,
      certificate.createdAt,
      certificate.updatedAt
    );

    return { valid: true, certificate: dto };
  }
}

class LearningProfileService {
  constructor(
    private profileRepo: LearningProfileRepository,
    private userRepo: UserRepository,
    private enrollmentRepo: EnrollmentRepository,
    private activityLogRepo: ActivityLogRepository,
    private cacheService: CacheService
  ) {}

  async createOrUpdateProfile(
    userId: string, 
    data: Partial<LearningProfile>
  ): Promise<LearningProfile> {
    const existing = await this.profileRepo.findByUser(userId);

    if (existing) {
      const updated = await this.profileRepo.update(existing.id, data);
      if (!updated) throw new HttpError(500, 'Failed to update learning profile');

      await this.cacheService.del(`learning_profile:${userId}`);
      await this.activityLogRepo.log(userId, 'update_learning_profile', 'learning_profile', existing.id);
      return updated;
    } else {
      const profile = await this.profileRepo.create({
        userId,
        learningStyle: data.learningStyle || LearningStyle.VISUAL,
        proficiencyLevel: data.proficiencyLevel || ProficiencyLevel.NOVICE,
        preferredDifficulty: data.preferredDifficulty || Level.BEGINNER,
        dailyStudyTime: data.dailyStudyTime || 30,
        strengths: data.strengths || [],
        weaknesses: data.weaknesses || [],
        lastActiveTime: data.lastActiveTime || '18:00',
        progressRate: data.progressRate || 0
      });

      await this.activityLogRepo.log(userId, 'create_learning_profile', 'learning_profile', profile.id);
      return profile;
    }
  }

  async analyzeLearningPatterns(userId: string): Promise<LearningProfile> {
    // تحليل أنماط التعلم بناءً على نشاط المستخدم
    const enrollments = await this.enrollmentRepo.findByUser(userId);
    const user = await this.userRepo.findById(userId);

    if (!user) throw new HttpError(404, 'User not found');

    // محاكاة تحليل أنماط التعلم (في التطبيق الحقيقي، ستكون هناك خوارزميات أكثر تعقيدًا)
    const learningStyle = this.determineLearningStyle(enrollments);
    const proficiency = this.calculateProficiencyLevel(enrollments);
    const activeTime = this.calculateActiveTimePattern(userId);

    const profileData: Partial<LearningProfile> = {
      learningStyle,
      proficiencyLevel: proficiency,
      lastActiveTime: activeTime,
      progressRate: this.calculateProgressRate(enrollments)
    };

    return this.createOrUpdateProfile(userId, profileData);
  }

  private determineLearningStyle(enrollments: Enrollment[]): LearningStyle {
    // محاكاة تحديد نمط التعلم (تطبيق حقيقي سيستخدم خوارزميات أكثر تقدمًا)
    const styles = Object.values(LearningStyle);
    return styles[Math.floor(Math.random() * styles.length)];
  }

  private calculateProficiencyLevel(enrollments: Enrollment[]): ProficiencyLevel {
    const completed = enrollments.filter(e => e.completedAt).length;
    const total = enrollments.length;
    const completionRate = total > 0 ? completed / total : 0;

    if (completionRate >= 0.8) return ProficiencyLevel.EXPERT;
    if (completionRate >= 0.6) return ProficiencyLevel.ADVANCED;
    if (completionRate >= 0.4) return ProficiencyLevel.INTERMEDIATE;
    return ProficiencyLevel.NOVICE;
  }

  private calculateActiveTimePattern(userId: string): string {
    // محاكاة تحديد الوقت النشط (تطبيق حقيقي سيحلل سجلات النشاط)
    const hours = ['08:00', '12:00', '15:00', '18:00', '20:00'];
    return hours[Math.floor(Math.random() * hours.length)];
  }

  private calculateProgressRate(enrollments: Enrollment[]): number {
    if (enrollments.length === 0) return 0;

    const totalProgress = enrollments.reduce((sum, enrollment) => {
      return sum + (enrollment.lessonsCompleted.length / 10); // Assuming 10 lessons per course on average
    }, 0);

    return totalProgress / enrollments.length;
  }
}

class RecommendationService {
  constructor(
    private recommendationRepo: RecommendationRepository,
    private courseRepo: CourseRepository,
    private roadmapRepo: RoadmapRepository,
    private challengeRepo: ChallengeRepository,
    private enrollmentRepo: EnrollmentRepository,
    private profileService: LearningProfileService,
    private cacheService: CacheService,
    private activityLogRepo: ActivityLogRepository
  ) {}

  async generateRecommendations(userId: string): Promise<Recommendation[]> {
    const cacheKey = `recommendations:${userId}`;
    const cached = await this.cacheService.get<Recommendation[]>(cacheKey);
    if (cached) return cached;

    const learningProfile = await this.profileService.analyzeLearningPatterns(userId);
    const userEnrollments = await this.enrollmentRepo.findByUser(userId);

    const enrolledCourseIds = userEnrollments.map((e: Enrollment) => e.courseId);
    const enrolledRoadmapIds: string[] = []; // سيتم ملؤها من بيانات المستخدم
    const enrolledChallengeIds: string[] = []; // سيتم ملؤها من بيانات المستخدم

    // الحصول على جميع الدورات والمسارات والتحديات المتاحة
    const [allCourses, allRoadmaps, allChallenges] = await Promise.all([
      this.courseRepo.findMany(),
      this.roadmapRepo.findMany(),
      this.challengeRepo.findMany()
    ]);

    // تصفية المحتوى غير المسجل فيه
    const availableCourses = allCourses.data.filter(c => 
      !enrolledCourseIds.includes(c.id) && 
      c.level === learningProfile.preferredDifficulty
    );

    const availableRoadmaps = allRoadmaps.data.filter(r =>
      !enrolledRoadmapIds.includes(r.id) &&
      r.difficulty === learningProfile.preferredDifficulty
    );

    const availableChallenges = allChallenges.data.filter(c =>
      !enrolledChallengeIds.includes(c.id) &&
      c.status === ChallengeStatus.ACTIVE
    );

    // توليد التوصيات بناءً على نمط التعلم والتفضيلات
    const recommendations = await this.generatePersonalizedRecommendations(
      userId,
      learningProfile,
      availableCourses,
      availableRoadmaps,
      availableChallenges
    );

    await this.cacheService.set(cacheKey, recommendations, 3600); // Cache for 1 hour
    await this.activityLogRepo.log(userId, 'generate_recommendations', 'recommendation', null);

    return recommendations;
  }

  private async generatePersonalizedRecommendations(
    userId: string,
    profile: LearningProfile,
    courses: Course[],
    roadmaps: Roadmap[],
    challenges: Challenge[]
  ): Promise<Recommendation[]> {
    const recommendations: Recommendation[] = [];

    // توصيات الدورات بناءً على نمط التعلم
    const courseRecommendations = courses
      .filter(course => this.matchesLearningStyle(course, profile.learningStyle))
      .slice(0, 5)
      .map(course => ({
        courseId: course.id,
        confidence: this.calculateConfidence(course, profile),
        reason: `Matches your ${profile.learningStyle} learning style`
      }));

    if (courseRecommendations.length > 0) {
      const courseRec = await this.recommendationRepo.create({
        userId,
        courseIds: courseRecommendations.map((c: any) => c.courseId),
        roadmapIds: [],
        challengeIds: [],
        confidenceScore: courseRecommendations.reduce((sum: number, c: any) => sum + c.confidence, 0) / courseRecommendations.length,
        reason: `Recommended based on your ${profile.learningStyle} learning style`
      });
      recommendations.push(courseRec);
    }

    // توصيات المسارات بناءً على مستوى الكفاءة
    const roadmapRecommendations = roadmaps
      .filter(roadmap => this.matchesProficiencyLevel(roadmap, profile.proficiencyLevel))
      .slice(0, 3)
      .map(roadmap => ({
        roadmapId: roadmap.id,
        confidence: this.calculateRoadmapConfidence(roadmap, profile),
        reason: `Appropriate for your ${profile.proficiencyLevel} skill level`
      }));

    if (roadmapRecommendations.length > 0) {
      const roadmapRec = await this.recommendationRepo.create({
        userId,
        courseIds: [],
        roadmapIds: roadmapRecommendations.map((r: any) => r.roadmapId),
        challengeIds: [],
        confidenceScore: roadmapRecommendations.reduce((sum: number, r: any) => sum + r.confidence, 0) / roadmapRecommendations.length,
        reason: `Recommended for your ${profile.proficiencyLevel} proficiency level`
      });
      recommendations.push(roadmapRec);
    }

    // توصيات التحديات بناءً على نقاط القوة والضعف
    const challengeRecommendations = challenges
      .filter(challenge => this.addressesWeaknesses(challenge, profile.weaknesses))
      .slice(0, 3)
      .map(challenge => ({
        challengeId: challenge.id,
        confidence: this.calculateChallengeConfidence(challenge, profile),
        reason: `Helps strengthen your ${profile.weaknesses.join(', ')} skills`
      }));

    if (challengeRecommendations.length > 0) {
      const challengeRec = await this.recommendationRepo.create({
        userId,
        courseIds: [],
        roadmapIds: [],
        challengeIds: challengeRecommendations.map((c: any) => c.challengeId),
        confidenceScore: challengeRecommendations.reduce((sum: number, c: any) => sum + c.confidence, 0) / challengeRecommendations.length,
        reason: `Addresses your learning needs in ${profile.weaknesses.join(', ')}`
      });
      recommendations.push(challengeRec);
    }

    return recommendations;
  }

  private matchesLearningStyle(course: Course, style: LearningStyle): boolean {
    // محاكاة مطابقة نمط التعلم (تطبيق حقيقي سيكون أكثر تعقيدًا)
    const styleWeights = {
      [LearningStyle.VISUAL]: course.tags.includes('visual') ? 0.9 : 0.3,
      [LearningStyle.AUDITORY]: course.tags.includes('audio') ? 0.9 : 0.3,
      [LearningStyle.KINESTHETIC]: course.tags.includes('interactive') ? 0.9 : 0.3,
      [LearningStyle.READING_WRITING]: course.tags.includes('reading') ? 0.9 : 0.3
    };

    return styleWeights[style] > 0.7;
  }

  private matchesProficiencyLevel(roadmap: Roadmap, level: ProficiencyLevel): boolean {
    const levelMapping = {
      [ProficiencyLevel.NOVICE]: Level.BEGINNER,
      [ProficiencyLevel.INTERMEDIATE]: Level.INTERMEDIATE,
      [ProficiencyLevel.ADVANCED]: Level.ADVANCED,
      [ProficiencyLevel.EXPERT]: Level.ADVANCED
    };

    return roadmap.difficulty === levelMapping[level];
  }

  private addressesWeaknesses(challenge: Challenge, weaknesses: string[]): boolean {
    // محاكاة معالجة نقاط الضعف (تطبيق حقيقي سيكون أكثر تعقيدًا)
    return weaknesses.some(weakness => 
      challenge.title.toLowerCase().includes(weakness.toLowerCase()) ||
      challenge.description.toLowerCase().includes(weakness.toLowerCase())
    );
  }

  private calculateConfidence(course: Course, profile: LearningProfile): number {
    // حساب ثقة التوصية بناءً على عوامل متعددة
    let confidence = 0.5;

    if (course.level === profile.preferredDifficulty) confidence += 0.2;
    if (this.matchesLearningStyle(course, profile.learningStyle)) confidence += 0.3;

    return Math.min(confidence, 0.95);
  }

  private calculateRoadmapConfidence(roadmap: Roadmap, profile: LearningProfile): number {
    let confidence = 0.5;

    if (roadmap.difficulty === profile.preferredDifficulty) confidence += 0.3;
    if (profile.strengths.some(strength => 
      roadmap.objectives.some(obj => obj.toLowerCase().includes(strength.toLowerCase())))
    ) confidence += 0.2;

    return Math.min(confidence, 0.95);
  }

  private calculateChallengeConfidence(challenge: Challenge, profile: LearningProfile): number {
    let confidence = 0.5;

    if (profile.weaknesses.some(weakness => 
      challenge.title.toLowerCase().includes(weakness.toLowerCase()) ||
      challenge.description.toLowerCase().includes(weakness.toLowerCase()))
    ) confidence += 0.4;

    return Math.min(confidence, 0.95);
  }
}

class AdaptiveLearningService {
  constructor(
    private courseRepo: CourseRepository,
    private lessonRepo: LessonRepository,
    private enrollmentRepo: EnrollmentRepository,
    private examAttemptRepo: ExamAttemptRepository,
    private cacheService: CacheService,
    private activityLogRepo: ActivityLogRepository
  ) {}

  async adjustContentDifficulty(
    userId: string, 
    courseId: string, 
    lessonId: string
  ): Promise<{ adjustedContent: string; difficulty: Level }> {
    const cacheKey = `adaptive_content:${userId}:${courseId}:${lessonId}`;
    const cached = await this.cacheService.get<{ adjustedContent: string; difficulty: Level }>(cacheKey);
    if (cached) return cached;

    const [enrollment, examAttempts, lesson] = await Promise.all([
      this.enrollmentRepo.findByUserAndCourse(userId, courseId),
      this.examAttemptRepo.findByUser(userId),
      this.lessonRepo.findById(lessonId)
    ]);

    if (!lesson) throw new HttpError(404, 'Lesson not found');

    const performance = this.calculatePerformance(userId, courseId, enrollment, examAttempts);
    const adjustedDifficulty = this.determineAppropriateDifficulty(performance);
    const adjustedContent = await this.adaptContent(lesson, adjustedDifficulty);

    const result = {
      adjustedContent,
      difficulty: adjustedDifficulty
    };

    await this.cacheService.set(cacheKey, result, 1800); // Cache for 30 minutes
    await this.activityLogRepo.log(userId, 'adjust_content_difficulty', 'lesson', lessonId, {
      courseId,
      originalDifficulty: lesson.durationMinutes > 30 ? Level.ADVANCED : Level.BEGINNER, // Simplified logic
      adjustedDifficulty
    });

    return result;
  }

  private calculatePerformance(
    userId: string, 
    courseId: string, 
    enrollment: Enrollment | null, 
    examAttempts: ExamAttempt[]
  ): number {
    if (!enrollment) return 0.5; // Default performance

    const courseAttempts = examAttempts.filter(attempt => 
      attempt.examId.includes(courseId) // Simplified assumption
    );

    const completionRate = enrollment.lessonsCompleted.length / 10; // Assuming 10 lessons per course
    const averageScore = courseAttempts.length > 0 ? 
      courseAttempts.reduce((sum, attempt) => sum + attempt.score, 0) / courseAttempts.length : 0;

    return (completionRate * 0.4) + (averageScore * 0.6);
  }

  private determineAppropriateDifficulty(performance: number): Level {
    if (performance >= 0.8) return Level.ADVANCED;
    if (performance >= 0.6) return Level.INTERMEDIATE;
    return Level.BEGINNER;
  }

  private async adaptContent(lesson: Lesson, difficulty: Level): Promise<string> {
    // محاكاة تكييف المحتوى (تطبيق حقيقي سيكون لديه محتوى مختلف لكل مستوى)
    const baseContent = lesson.description;

    switch (difficulty) {
      case Level.BEGINNER:
        return `BEGINNER LEVEL: ${baseContent}\n\nAdditional explanations and examples provided for beginners.`;
      case Level.INTERMEDIATE:
        return `INTERMEDIATE LEVEL: ${baseContent}\n\nStandard content with balanced detail.`;
      case Level.ADVANCED:
        return `ADVANCED LEVEL: ${baseContent}\n\nAdvanced concepts and challenging applications.`;
      default:
        return baseContent;
    }
  }

  async generatePersonalizedLearningPath(
    userId: string, 
    goal: string,
    timeframeWeeks: number = 12
  ): Promise<LearningPath> {
    const userEnrollments = await this.enrollmentRepo.findByUser(userId);
    const allCourses = await this.courseRepo.findMany();

    const availableCourses = allCourses.data.filter(course => 
      !userEnrollments.some(e => e.courseId === course.id)
    );

    // خوارزمية مبسطة لإنشاء مسار تعلم مخصص
    const selectedCourses = this.selectCoursesForGoal(availableCourses, goal)
      .slice(0, 3); // Limit to 3 courses for the path

    const pathCourses = selectedCourses.map((course, index) => ({
      courseId: course.id,
      order: index + 1,
      expectedStart: dayjs().add(index * 4, 'weeks').toISOString(),
      expectedEnd: dayjs().add((index + 1) * 4, 'weeks').toISOString(),
      status: 'pending' as const
    }));

    const learningPath = {
      userId,
      goal,
      estimatedCompletion: dayjs().add(timeframeWeeks, 'weeks').toISOString(),
      courses: pathCourses,
      progress: 0
    };

    await this.activityLogRepo.log(userId, 'generate_learning_path', 'learning_path', null, {
      goal,
      courses: selectedCourses.map(c => c.id)
    });

    return learningPath as LearningPath;
  }

  private selectCoursesForGoal(courses: Course[], goal: string): Course[] {
    // محاكاة اختيار الدورات المناسبة للهدف (تطبيق حقيقي سيكون أكثر تعقيدًا)
    const goalKeywords = goal.toLowerCase().split(' ');

    return courses
      .map(course => {
        const relevance = goalKeywords.filter(keyword => 
          course.title.toLowerCase().includes(keyword) ||
          course.description.toLowerCase().includes(keyword) ||
          course.tags.some(tag => tag.toLowerCase().includes(keyword))
        ).length;

        return { course, relevance };
      })
      .filter(item => item.relevance > 0)
      .sort((a, b) => b.relevance - a.relevance)
      .map(item => item.course);
  }
}

class AdvancedAnalyticsService {
  constructor(
    private userRepo: UserRepository,
    private enrollmentRepo: EnrollmentRepository,
    private examAttemptRepo: ExamAttemptRepository,
    private lessonRepo: LessonRepository,
    private cacheService: CacheService,
    private activityLogRepo: ActivityLogRepository
  ) {}

  async predictCourseCompletion(userId: string, courseId: string): Promise<PredictiveAnalytic> {
    const cacheKey = `completion_prediction:${userId}:${courseId}`;
    const cached = await this.cacheService.get<PredictiveAnalytic>(cacheKey);
    if (cached) return cached;

    const [enrollment, examAttempts, lessons] = await Promise.all([
      this.enrollmentRepo.findByUserAndCourse(userId, courseId),
      this.examAttemptRepo.findByUserAndExam(userId, courseId), // Simplified assumption
      this.lessonRepo.findByCourse(courseId)
    ]);

    if (!enrollment) {
      throw new HttpError(404, 'Enrollment not found');
    }

    const completionProbability = this.calculateCompletionProbability(enrollment, examAttempts, lessons);
    const predictedGrade = this.predictGrade(examAttempts);
    const riskFactors = this.identifyRiskFactors(enrollment, examAttempts, lessons);
    const recommendedInterventions = this.suggestInterventions(riskFactors);

    const prediction: PredictiveAnalytic = {
      userId,
      courseId,
      completionProbability,
      predictedGrade,
      riskFactors,
      recommendedInterventions,
      id: uuidv4(),
      createdAt: dayjs().toISOString(),
      updatedAt: dayjs().toISOString(),
      deletedAt: null
    };

    await this.cacheService.set(cacheKey, prediction, 86400); // Cache for 24 hours
    await this.activityLogRepo.log(userId, 'predict_course_completion', 'analytics', courseId, {
      probability: completionProbability,
      predictedGrade
    });

    return prediction;
  }

  private calculateCompletionProbability(
    enrollment: Enrollment,
    examAttempts: ExamAttempt[],
    lessons: Lesson[]
  ): number {
    if (enrollment.completedAt) return 1.0;

    const lessonsCompleted = enrollment.lessonsCompleted.length;
    const totalLessons = lessons.length;
    const completionRatio = lessonsCompleted / totalLessons;

    const avgExamScore = examAttempts.length > 0 ?
      examAttempts.reduce((sum, attempt) => sum + attempt.score, 0) / examAttempts.length : 0;

    const engagementScore = this.calculateEngagementScore(enrollment, examAttempts);

    // نموذج تنبؤي مبسط
    let probability = (completionRatio * 0.4) + (avgExamScore * 0.4) + (engagementScore * 0.2);

    // عوامل إضافية
    const daysSinceLastActivity = dayjs().diff(dayjs(enrollment.updatedAt), 'days');
    if (daysSinceLastActivity > 30) probability *= 0.7;
    if (daysSinceLastActivity > 60) probability *= 0.5;

    return Math.min(Math.max(probability, 0), 1);
  }

  private calculateEngagementScore(enrollment: Enrollment, examAttempts: ExamAttempt[]): number {
    // حساب درجة المشاركة بناءً على النشاط
    const lessonCompletionRate = enrollment.lessonsCompleted.length / 10; // Assuming 10 lessons
    const examAttemptRate = examAttempts.length / 3; // Assuming 3 exams per course

    return (lessonCompletionRate * 0.6) + (examAttemptRate * 0.4);
  }

  private predictGrade(examAttempts: ExamAttempt[]): string {
    if (examAttempts.length === 0) return 'B'; // Default prediction

    const latestScore = examAttempts[examAttempts.length - 1].score;

    if (latestScore >= 90) return 'A';
    if (latestScore >= 80) return 'B';
    if (latestScore >= 70) return 'C';
    if (latestScore >= 60) return 'D';
    return 'F';
  }

  private identifyRiskFactors(
    enrollment: Enrollment,
    examAttempts: ExamAttempt[],
    lessons: Lesson[]
  ): string[] {
    const riskFactors: string[] = [];
    const now = dayjs();

    // تحليل عوامل الخطر
    const lastActivityDate = dayjs(enrollment.updatedAt);
    const daysInactive = now.diff(lastActivityDate, 'days');

    if (daysInactive > 14) {
      riskFactors.push(`Inactive for ${daysInactive} days`);
    }

    if (examAttempts.length > 0) {
      const latestAttempt = examAttempts[examAttempts.length - 1];
      if (latestAttempt.score < 60) {
        riskFactors.push('Low exam scores');
      }
    }

    const completionRate = enrollment.lessonsCompleted.length / lessons.length;
    if (completionRate < 0.3) {
      riskFactors.push('Low lesson completion rate');
    }

    if (enrollment.lessonsCompleted.length === 0 && daysInactive > 7) {
      riskFactors.push('No progress made');
    }

    return riskFactors;
  }

  private suggestInterventions(riskFactors: string[]): string[] {
    const interventions: string[] = [];

    if (riskFactors.some(factor => factor.includes('Inactive'))) {
      interventions.push('Send motivational notification');
      interventions.push('Schedule reminder emails');
    }

    if (riskFactors.some(factor => factor.includes('Low exam scores'))) {
      interventions.push('Recommend practice exercises');
      interventions.push('Suggest peer tutoring');
    }

    if (riskFactors.some(factor => factor.includes('Low lesson completion'))) {
      interventions.push('Adjust content difficulty');
      interventions.push('Provide additional learning resources');
    }

    if (riskFactors.some(factor => factor.includes('No progress'))) {
      interventions.push('Personalized check-in from instructor');
      interventions.push('Learning path reassessment');
    }

    return interventions;
  }

  async identifyAtRiskStudents(courseId: string, threshold: number = 0.4): Promise<AtRiskStudent[]> {
    const enrollments = await this.enrollmentRepo.findMany({ courseId });
    const atRiskStudents: AtRiskStudent[] = [];

    for (const enrollment of enrollments.data) {
      if (enrollment.completedAt) continue; // Skip completed enrollments

      const prediction = await this.predictCourseCompletion(enrollment.userId, courseId);

      if (prediction.completionProbability < threshold) {
        const user = await this.userRepo.findById(enrollment.userId);
        if (user) {
          atRiskStudents.push({
            userId: user.id,
            userName: user.name,
            email: user.email,
            completionProbability: prediction.completionProbability,
            riskFactors: prediction.riskFactors,
            recommendedInterventions: prediction.recommendedInterventions,
            lastActivity: enrollment.updatedAt
          });
        }
      }
    }

    await this.activityLogRepo.log('system', 'identify_at_risk_students', 'analytics', courseId, {
      count: atRiskStudents.length,
      threshold
    });

    return atRiskStudents;
  }
}

// Middlewares
class AuthMiddleware {
  static authenticate() {
    return passport.authenticate('jwt', { session: false });
  }

  static initializePassport() {
    // Local  for email/password login
    passport.use(
      new Local(
        {
          usernameField: 'email',
          passwordField: 'password'
        },
        async (email: string, password: string, done: (error: any, user?: any) => void) => {
          try {
            const user = await userRepo.findByEmail(email);
            if (!user) return done(null, false, { message: 'Invalid credentials' });
            if (user.isBlocked) return done(null, false, { message: 'User blocked' });

            const match = await bcrypt.compare(password, user.passwordHash);
            if (!match) return done(null, false, { message: 'Invalid credentials' });

            return done(null, user);
          } catch (error) {
            return done(error);
          }
        }
      )
    );

    // JWT  for bearer token authentication
    // In AuthMiddleware, ensure JWT payload is properly parsed
// In AuthMiddleware class
  passport.use(
    new Jwt(
      {
        jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
        secretOrKey: JWT_SECRET,
        ignoreExpiration: false
      },
      async (payload: any, done: (error: any, user?: any) => void) => {
        try {
          if (!payload?.userId) {
            return done(null, false);
          }

          const user = await userRepo.findById(payload.userId);
          if (!user || user.deletedAt || user.isBlocked) {
            return done(null, false);
          }

          return done(null, user);
        } catch (error) {
          return done(error, false);
        }
      }
    )
  );


    passport.serializeUser((user: User, done: (err: any, id?: string) => void) =>  {
      done(null, user.id);
    });

    passport.deserializeUser(async (id: string, done: (err: any, user?: any) => void) =>  {
      try {
        const user = await userRepo.findById(id, true);
        if (!user || user.deletedAt) {
          return done(null, false);
        }
        done(null, user);
      } catch (error) {
        done(error);
      }
    });

    return passport.initialize();
  }
}



class RBACMiddleware {
  static checkRole(roles: Role[]) {
    return (req: Request, res: Response, next: NextFunction) => {
      const user = req.user as User | undefined;
      if (!user) return res.status(401).json({ success: false, error: 'Unauthorized' });
      if (!roles.includes(user.role)) {
        return res.status(403).json({ success: false, error: 'Forbidden' });
      }
      next();
    };
  }
}

class RequestIdMiddleware {
  static generate() {
    return (req: Request, res: Response, next: NextFunction) => {
      const requestId = uuidv4();
      res.setHeader('X-Request-Id', requestId);
      next();
    };
  }
}

class UploadMiddleware {
  static setup() {
    const storage = multer.memoryStorage(); // Use memory storage for serverless environments

    const fileFilter = (req: Request, file: Express.Multer.File, cb: FileFilterCallback) => {
  const imageMimes = ['image/jpeg', 'image/png', 'image/webp', 'image/gif'];
  const videoMimes = ['video/mp4', 'video/quicktime', 'video/x-msvideo'];
  const docMimes = [
    'application/pdf', 
    'application/msword', 
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document', 
    'application/zip'
  ];

  if (file.fieldname === 'profile' || file.fieldname === 'thumbnail') {
    if (imageMimes.includes(file.mimetype)) return cb(null, true);
  } else if (file.fieldname === 'video') {
    if (videoMimes.includes(file.mimetype)) return cb(null, true);
  } else if (file.fieldname === 'attachment') {
    if (docMimes.includes(file.mimetype)) return cb(null, true);
  }

  cb(new Error(`Invalid file type: ${file.mimetype}`));
};

    return multer({
      storage,
      fileFilter,
      limits: {
        fileSize: 50 * 1024 * 1024, // 50MB
      },
    });
  }
}

class ValidationMiddleware {
  static validate(schema: z.ZodSchema) {
    return (req: Request, res: Response, next: NextFunction) => {
      try {
        schema.parse(req.body);
        next();
      } catch (error) {
        if (error instanceof ZodError) {
          res.status(400).json({
            success: false,
            error: {
              code: 'VALIDATION_ERROR',
              message: 'Invalid input',
              details: error.errors,
            },
          });
        } else {
          next(error);
        }
      }
    };
  }
}

class ErrorHandler {
  static handle() {
    return (err: any, req: Request, res: Response, next: NextFunction) => {
      if (err instanceof HttpError) {
        res.status(err.statusCode).json({
          success: false,
          error: {
            code: 'HTTP_ERROR',
            message: err.message,
            details: err.details,
          },
        });
      } else if (err instanceof ZodError) {
        res.status(400).json({
          success: false,
          error: {
            code: 'VALIDATION_ERROR',
            message: 'Invalid input',
            details: err.errors,
          },
        });
      } else {
        logger.error(`Internal server error: ${err}`);
        res.status(500).json({
          success: false,
          error: {
            code: 'INTERNAL_SERVER_ERROR',
            message: 'Internal server error',
          },
        });
      }
    };
  }
}

// Zod Schemas
const registerSchema = z.object({
  name: z.string().min(3),
  email: z.string().email(),
  password: z.string().min(8).regex(
    /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/,
    'Password must contain at least one uppercase, one lowercase, one number, and one special character'
  ),
  phoneNumber: z.string().min(8),
  role: z.nativeEnum(Role),
  dateOfBirth: z.string().optional(), // أضف هذا الحقل
  country: z.string().optional(), // أضف هذا الحقل
  gender: z.nativeEnum(Gender).optional(), // أضف هذا الحقل
});

const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
});

const refreshSchema = z.object({
  refreshToken: z.string(),
});

const lessonCreateSchema = z.object({
  courseId: z.string(),
  title: z.string().min(3),
  description: z.string(),
  videoUrl: z.string().url(),
  attachments: z.array(z.string()).optional(),
  thumbnailUrl: z.string().url(),
  instructorId: z.string(),
  durationMinutes: z.number().positive(),
});

const assignInstructorSchema = z.object({
  instructorId: z.string(),
  hrId: z.string(),
});

// Repositories
const userRepo = new UserRepository();
const courseRepo = new CourseRepository();
const lessonRepo = new LessonRepository();
const categoryRepo = new CategoryRepository();
const enrollmentRepo = new EnrollmentRepository();
const conversationRepo = new SupportConversationRepository();
const refreshTokenRepo = new RefreshTokenRepository();
const activityLogRepo = new ActivityLogRepository();
// Initialize new repositories
const roadmapRepo = new RoadmapRepository();
const challengeRepo = new ChallengeRepository();
const examRepo = new ExamRepository();
const attemptRepo = new ExamAttemptRepository();
const certificateRepo = new CertificateRepository();
const learningProfileRepo = new LearningProfileRepository();
const recommendationRepo = new RecommendationRepository();




// Initialize new services







// Services
const cacheService = new CacheService(redisClient);
const authService = new AuthService(userRepo, refreshTokenRepo, cacheService, activityLogRepo);
const userService = new UserService(
  userRepo,
  enrollmentRepo,
  conversationRepo,
  cacheService,
  activityLogRepo,
  firebaseStorageService
);
const courseService = new CourseService(
  courseRepo,
  lessonRepo,
  categoryRepo,
  cacheService,
  activityLogRepo,
  userRepo,
  firebaseStorageService
);

const lessonService = new LessonService(lessonRepo, courseRepo, cacheService, activityLogRepo, userRepo);
const categoryService = new CategoryService(categoryRepo, cacheService, activityLogRepo);
const enrollmentService = new EnrollmentService(enrollmentRepo, userRepo, courseRepo, cacheService, activityLogRepo);
const supportService = new SupportService(conversationRepo, userRepo, cacheService, activityLogRepo);
const reportService = new ReportService(
  userRepo, 
  enrollmentRepo, 
  conversationRepo, 
  lessonRepo,
  firebaseStorageService
);
const adminService = new AdminService(
  userRepo, courseRepo, lessonRepo, categoryRepo, 
  enrollmentRepo, conversationRepo, supportService
);
const hrService = new HrService(userRepo);
const binService = new BinService(
  userRepo, courseRepo, lessonRepo, categoryRepo, 
  enrollmentRepo, conversationRepo
);
const snapshotService = new SnapshotService();

const roadmapService = new RoadmapService(roadmapRepo, courseRepo, userRepo, cacheService, activityLogRepo);
const challengeService = new ChallengeService(challengeRepo, userRepo, cacheService, activityLogRepo);
const examService = new ExamService(
  examRepo,
  attemptRepo,
  certificateRepo,
  userRepo,
  courseRepo,
  cacheService,
  activityLogRepo,
  firebaseStorageService
);

// تهيئة services الجديدة
const learningProfileService = new LearningProfileService(
  learningProfileRepo,
  userRepo,
  enrollmentRepo,
  activityLogRepo,
  cacheService
);

const recommendationService = new RecommendationService(
  recommendationRepo,
  courseRepo,
  roadmapRepo,
  challengeRepo,
  enrollmentRepo, // أضف هذا
  learningProfileService,
  cacheService,
  activityLogRepo
);

const adaptiveLearningService = new AdaptiveLearningService(
  courseRepo,
  lessonRepo,
  enrollmentRepo,
  attemptRepo, // استخدام المتغير الصحيح
  cacheService,
  activityLogRepo
);

const advancedAnalyticsService = new AdvancedAnalyticsService(
  userRepo,
  enrollmentRepo,
  attemptRepo, // استخدام المتغير الصحيح
  lessonRepo,
  cacheService,
  activityLogRepo
);

// Controllers
class AuthController {
  static async register(req: Request, res: Response) {
    const data = registerSchema.parse(req.body);
    const result = await authService.register(
      data.name,
      data.email,
      data.password,
      data.phoneNumber,
      data.role
    );
    res.json({ success: true, data: result });
  }

  static async login(req: Request, res: Response) {
    const data = loginSchema.parse(req.body);
    const result = await authService.login(data.email, data.password);
    res.json({ success: true, data: result });
  }

  static async refreshToken(req: Request, res: Response) {
    const data = refreshSchema.parse(req.body);
    const result = await authService.refreshToken(data.refreshToken);
    res.json({ success: true, data: result });
  }

  static async logout(req: Request, res: Response) {
    const data = refreshSchema.parse(req.body);
    await authService.logout(data.refreshToken);
    res.json({ success: true, data: { message: 'Logged out' } });
  }
}

class UserController {
  // In UserController, add proper error handling
static async getUser(req: Request, res: Response) {
  try {
    const user = await userService.getUserById(req.params.id);
    if (!user) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }
    res.json({ success: true, data: user });
  } catch (error) {
    logger.error(`Error getting user: ${error}`);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
}

  static async updateUser(req: Request, res: Response) {
    const user = await userService.updateUser(req.params.id, req.body);
    res.json({ success: true, data: user });
  }

  static async blockUser(req: Request, res: Response) {
    await userService.blockUser(req.params.id);
    res.json({ success: true, data: { message: 'User blocked' } });
  }

  static async unblockUser(req: Request, res: Response) {
    await userService.unblockUser(req.params.id);
    res.json({ success: true, data: { message: 'User unblocked' } });
  }

  static async softDeleteUser(req: Request, res: Response) {
    await userService.softDeleteUser(req.params.id);
    res.json({ success: true, data: { message: 'User soft deleted' } });
  }

  static async restoreUser(req: Request, res: Response) {
    await userService.restoreUser(req.params.id);
    res.json({ success: true, data: { message: 'User restored' } });
  }

  static async getUserReport(req: Request, res: Response) {
    const userId = req.params.id;
    const report = await reportService.generateUserReport(userId);

    if (req.query.format === ExportFormat.CSV || req.query.format === ExportFormat.PDF) {
      const filePath = await reportService.exportReport(report, req.query.format as ExportFormat);
      res.download(filePath);
    } else {
      res.json({ success: true, data: report });
    }
  }
  // Add to UserController
// في UserController، عدّل دالة getUsers
static async getUsers(req: Request, res: Response) {
  const { role, limit = 100, cursor } = req.query;
  const users = await userService.getUsers(
    role as Role | undefined,
    parseInt(limit as string),
    cursor as string | undefined
  );
  
  // إرجاع النتيجة مع مؤشر الترحيل
  res.json({ 
    success: true, 
    data: {
      users: users,
      nextCursor: users.length === parseInt(limit as string) ? users[users.length - 1].id : null
    }
  });
}


}

class CourseController {
  // في CourseController، عدّل دالة getCoursesPublic
static async getCoursesPublic(req: Request, res: Response , next: NextFunction) {
  try {
    const { limit = 100, cursor } = req.query;
    const result = await courseService.getCoursesPublic(
      parseInt(limit as string),
      cursor as string | undefined
    );
    
    res.json({ 
      success: true, 
      data: {
        courses: result.data,
        nextCursor: result.nextCursor
      }
    });
  } catch (error) {
    next(error);
  }
}
  static async createCourse(req: Request, res: Response) {
    const course = await courseService.createCourse(req.body);
    res.json({ success: true, data: course });
  }

  static async getCourse(req: Request, res: Response) {
    const course = await courseService.getCourseById(req.params.id);
    res.json({ success: true, data: course });
  }

  static async updateCourse(req: Request, res: Response) {
    const course = await courseService.updateCourse(req.params.id, req.body);
    res.json({ success: true, data: course });
  }

  static async softDeleteCourse(req: Request, res: Response) {
    await courseService.softDeleteCourse(req.params.id);
    res.json({ success: true, data: { message: 'Course soft deleted' } });
  }

  static async restoreCourse(req: Request, res: Response) {
    await courseService.restoreCourse(req.params.id);
    res.json({ success: true, data: { message: 'Course restored' } });
  }
}

class LessonController {
  static async createLesson(req: Request, res: Response) {
    const data = lessonCreateSchema.parse(req.body);

const lessonInput = {
  ...data,
  attachments: data.attachments || []  // Ensure attachments is always an array
};
const lesson = await lessonService.createLesson(lessonInput);
    res.json({ success: true, data: lesson });
  }

  static async getLesson(req: Request, res: Response) {
    const lesson = await lessonService.getLessonById(req.params.id);
    res.json({ success: true, data: lesson });
  }

  static async updateLesson(req: Request, res: Response) {
    const lesson = await lessonService.updateLesson(req.params.id, req.body);
    res.json({ success: true, data: lesson });
  }

  static async softDeleteLesson(req: Request, res: Response) {
    await lessonService.softDeleteLesson(req.params.id);
    res.json({ success: true, data: { message: 'Lesson soft deleted' } });
  }

  static async restoreLesson(req: Request, res: Response) {
    await lessonService.restoreLesson(req.params.id);
    res.json({ success: true, data: { message: 'Lesson restored' } });
  }

  static async permanentDeleteLesson(req: Request, res: Response) {
    await lessonService.permanentDeleteLesson(req.params.id);
    res.json({ success: true, data: { message: 'Lesson permanently deleted' } });
  }

  static async getLessonsByCourse(req: Request, res: Response) {
    const { limit, cursor } = req.query;
    const lessons = await lessonService.getLessonsByCourse(
      req.params.courseId,
      parseInt(limit as string) || 10,
      cursor as string
    );
    res.json({ success: true, data: lessons });
  }
}

class CategoryController {
  static async createCategory(req: Request, res: Response) {
    const category = await categoryService.createCategory(req.body.name, req.body.description);
    res.json({ success: true, data: category });
  }

  static async getCategory(req: Request, res: Response) {
    const category = await categoryService.getCategoryById(req.params.id);
    res.json({ success: true, data: category });
  }

  static async updateCategory(req: Request, res: Response) {
    const category = await categoryService.updateCategory(req.params.id, req.body);
    res.json({ success: true, data: category });
  }

  static async softDeleteCategory(req: Request, res: Response) {
    await categoryService.softDeleteCategory(req.params.id);
    res.json({ success: true, data: { message: 'Category soft deleted' } });
  }

  static async restoreCategory(req: Request, res: Response) {
    await categoryService.restoreCategory(req.params.id);
    res.json({ success: true, data: { message: 'Category restored' } });
  }

  static async permanentDeleteCategory(req: Request, res: Response) {
    await categoryService.permanentDeleteCategory(req.params.id);
    res.json({ success: true, data: { message: 'Category permanently deleted' } });
  }
}

class EnrollmentController {
  static async enroll(req: Request, res: Response) {
    const enrollment = await enrollmentService.enrollStudent(req.body.userId, req.body.courseId);
    res.json({ success: true, data: enrollment });
  }

  // في EnrollmentController، عدّل دالة updateProgress
static async updateProgress(req: Request, res: Response , next: NextFunction ) {
  try {
    const { enrollmentId, lessonId, rating, completed } = req.body;
    
    if (!enrollmentId || !lessonId) {
      throw new HttpError(400, 'معرّف التسجيل ومعرّف الدرس مطلوبان');
    }
    
    const result = await enrollmentService.updateProgress(
      enrollmentId, 
      lessonId, 
      rating
    );
    
    res.json({ 
      success: true, 
      data: result 
    });
  } catch (error) {
    next(error);
  }
}
}

class SupportController {
  static async createConversation(req: Request, res: Response) {
    const conversation = await supportService.createConversation(req.body.userId);
    res.json({ success: true, data: conversation });
  }

  static async addMessage(req: Request, res: Response) {
    const message = await supportService.addMessage(req.params.id, req.body.senderId, req.body.content);
    res.json({ success: true, data: message });
  }
}

class AdminController {
  static async getDashboard(req: Request, res: Response) {
    const dashboard = await adminService.getDashboard();
    res.json({ success: true, data: dashboard });
  }
}

class HrController {
  static async getInstructors(req: Request, res: Response) {
    const instructors = await hrService.getInstructors();
    res.json({ success: true, data: instructors });
  }

  static async assignInstructor(req: Request, res: Response) {
    const data = assignInstructorSchema.parse(req.body);
    await hrService.assignInstructor(data.instructorId, data.hrId);
    res.json({ success: true, data: { message: 'Instructor assigned' } });
  }
}

class BinController {
  static async getDeletedItems(req: Request, res: Response) {
    const items = await binService.getDeletedItems();
    res.json({ success: true, data: items });
  }

  static async restoreItem(req: Request, res: Response) {
    const { collection, id } = req.params;
    let result: boolean;

    switch (collection) {
      case 'users':
        result = await userService.restoreUser(id);
        break;
      case 'courses':
        result = await courseService.restoreCourse(id);
        break;
      case 'lessons':
        result = await lessonService.restoreLesson(id);
        break;
      case 'categories':
        result = await categoryService.restoreCategory(id);
        break;
      default:
        throw new HttpError(400, 'Invalid collection');
    }

    res.json({ success: true, data: { restored: result } });
  }

  static async permanentDelete(req: Request, res: Response) {
    const { collection, id } = req.params;
    let result: boolean;

    switch (collection) {
      case 'users':
        result = await userRepo.permanentDelete(id);
        break;
      case 'courses':
        result = await courseRepo.permanentDelete(id);
        break;
      case 'lessons':
        result = await lessonService.permanentDeleteLesson(id);
        break;
      case 'categories':
        result = await categoryService.permanentDeleteCategory(id);
        break;
      default:
        throw new HttpError(400, 'Invalid collection');
    }

    res.json({ success: true, data: { deleted: result } });
  }
}

class RoadmapController {
  static async createRoadmap(req: Request, res: Response) {
    const roadmap = await roadmapService.createRoadmap(req.body);
    res.json({ success: true, data: roadmap });
  }

  static async getRoadmap(req: Request, res: Response) {
    const roadmap = await roadmapService.getRoadmapById(req.params.id, req.user?.id);
    res.json({ success: true, data: roadmap });
  }

  static async getRoadmaps(req: Request, res: Response) {
    const { limit = 10, cursor } = req.query;
    const result = await roadmapService.getRoadmaps(
      parseInt(limit as string),
      cursor as string | undefined
    );
    res.json({ success: true, data: result });
  }

  static async enrollRoadmap(req: Request, res: Response) {
    await roadmapService.enrollUser(req.params.id, req.body.userId);
    res.json({ success: true, data: { message: 'Enrolled successfully' } });
  }
}

class ChallengeController {
  static async createChallenge(req: Request, res: Response) {
    const challenge = await challengeService.createChallenge(req.body);
    res.json({ success: true, data: challenge });
  }

  static async getChallenge(req: Request, res: Response) {
    const challenge = await challengeService.getChallengeById(req.params.id, req.user?.id);
    res.json({ success: true, data: challenge });
  }

  static async getChallenges(req: Request, res: Response) {
    const { type, limit = 10, cursor } = req.query;
    const result = await challengeService.getChallenges(
      type as 'active' | 'upcoming' | 'ended' | undefined,
      parseInt(limit as string),
      cursor as string | undefined
    );
    res.json({ success: true, data: result });
  }

  static async submitChallenge(req: Request, res: Response) {
    const result = await challengeService.submitChallengeAnswers(
      req.params.id,
      req.user!.id,
      req.body.answers,
      req.body.timeSpent
    );
    res.json({ success: true, data: result });
  }

  static async getLeaderboard(req: Request, res: Response) {
    const leaderboard = await challengeService.getLeaderboard(req.params.id);
    res.json({ success: true, data: leaderboard });
  }
}

class ExamController {
  static async createExam(req: Request, res: Response) {
    const exam = await examService.createExam(req.body);
    res.json({ success: true, data: exam });
  }

  static async getExam(req: Request, res: Response) {
    const exam = await examService.getExamById(req.params.id);
    res.json({ success: true, data: exam });
  }

  static async submitExam(req: Request, res: Response) {
    const result = await examService.submitExam(
      req.params.id,
      req.user!.id,
      req.body.answers,
      req.body.timeSpent
    );
    res.json({ success: true, data: result });
  }

  static async getCertificates(req: Request, res: Response) {
    const certificates = await examService.getCertificatesByUser(req.user!.id);
    res.json({ success: true, data: certificates });
  }

  static async verifyCertificate(req: Request, res: Response) {
    const result = await examService.verifyCertificate(req.params.code);
    res.json({ success: true, data: result });
  }
}

class LearningProfileController {
  static async createOrUpdateProfile(req: Request, res: Response) {
    const profile = await learningProfileService.createOrUpdateProfile(
      req.params.userId,
      req.body
    );
    res.json({ success: true, data: profile });
  }

  static async analyzeLearningPatterns(req: Request, res: Response) {
    const profile = await learningProfileService.analyzeLearningPatterns(req.params.userId);
    res.json({ success: true, data: profile });
  }
}

class RecommendationController {
  static async getRecommendations(req: Request, res: Response) {
    const recommendations = await recommendationService.generateRecommendations(req.params.userId);
    res.json({ success: true, data: recommendations });
  }
}

class AdaptiveLearningController {
  static async adjustContentDifficulty(req: Request, res: Response) {
    const result = await adaptiveLearningService.adjustContentDifficulty(
      req.params.userId,
      req.params.courseId,
      req.params.lessonId
    );
    res.json({ success: true, data: result });
  }

  static async generateLearningPath(req: Request, res: Response) {
    const learningPath = await adaptiveLearningService.generatePersonalizedLearningPath(
      req.params.userId,
      req.body.goal,
      req.body.timeframeWeeks
    );
    res.json({ success: true, data: learningPath });
  }
}

class AnalyticsController {
  static async predictCompletion(req: Request, res: Response) {
    const prediction = await advancedAnalyticsService.predictCourseCompletion(
      req.params.userId,
      req.params.courseId
    );
    res.json({ success: true, data: prediction });
  }

  static async getAtRiskStudents(req: Request, res: Response) {
    const atRiskStudents = await advancedAnalyticsService.identifyAtRiskStudents(
      req.params.courseId,
      parseFloat(req.query.threshold as string) || 0.4
    );
    res.json({ success: true, data: atRiskStudents });
  }
}


// Initialize Express app
const app = express();

// Middleware stack
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(helmet());
app.use(ErrorHandler.handle());
app.use(cors({ origin: process.env.CORS_ORIGIN || '*' }));
app.use(compression());

app.use(
  rateLimit({
    windowMs: 60 * 1000, // 1 minute
    max: 5,
    skip: (req: Request) => req.ip === '127.0.0.1',
    message: 'Too many auth attempts, please try again later',
    skipFailedRequests: true,
    keyGenerator: (req: Request) => {
      const ip = req.ip || req.connection.remoteAddress || 'unknown-ip';
      return `${ip}-${req.path}`;
    },
  })
);

app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    skip: (req: Request) => req.ip === '127.0.0.1',
  })
);
app.use(morgan('combined', { stream: { write: (message: string) => logger.info(message.trim()) } }));
app.use(RequestIdMiddleware.generate());
app.use(AuthMiddleware.initializePassport());
// إزالة هذا السطر أو تعديله:
// app.use('/uploads', express.static(UPLOAD_DIR));

// يمكنك استبداله بـ:
app.use('/uploads', (req, res) => {
  res.status(404).json({ error: 'Static file serving is disabled in serverless environment' });
});

// Swagger setup
const swaggerOptions = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'Sinceides Platform API',
      version: '1.0.0',
      description: 'API documentation for Sinceides LMS Platform',
    },
    servers: [{ url: `http://localhost:${PORT}/api` }],
    components: {
      securitySchemes: {
        bearerAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT',
        },
      },
    },
    security: [{ bearerAuth: [] }],
  },
  apis: ['app.ts'],
};

const swaggerSpec = swaggerJsdoc(swaggerOptions);
app.use('/docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));

// Routes
const apiRouter = Router();

// Auth routes
apiRouter.post('/auth/register', ValidationMiddleware.validate(registerSchema), AuthController.register);
apiRouter.post('/auth/login', ValidationMiddleware.validate(loginSchema), AuthController.login);
apiRouter.post('/auth/refresh', ValidationMiddleware.validate(refreshSchema), AuthController.refreshToken);
apiRouter.post('/auth/logout', ValidationMiddleware.validate(refreshSchema), AuthController.logout);

// User routes
apiRouter.get('/users/:id', AuthMiddleware.authenticate(),  UserController.getUser);
apiRouter.put('/users/:id', AuthMiddleware.authenticate(),  UserController.updateUser);
apiRouter.get('/users/:id/report', AuthMiddleware.authenticate(),  UserController.getUserReport);
apiRouter.delete('/users/:id', AuthMiddleware.authenticate(), RBACMiddleware.checkRole([Role.ADMIN]), UserController.softDeleteUser);
apiRouter.post('/users/:id/restore', AuthMiddleware.authenticate(), RBACMiddleware.checkRole([Role.ADMIN]), UserController.restoreUser);
apiRouter.put('/users/:id/block', AuthMiddleware.authenticate(), RBACMiddleware.checkRole([Role.ADMIN]), UserController.blockUser);
apiRouter.put('/users/:id/unblock', AuthMiddleware.authenticate(), RBACMiddleware.checkRole([Role.ADMIN]), UserController.unblockUser);
// Add this route in your routes section
apiRouter.get('/users', AuthMiddleware.authenticate(), RBACMiddleware.checkRole([Role.ADMIN, Role.HR]), UserController.getUsers);

// Roadmap routes
apiRouter.post('/roadmaps', AuthMiddleware.authenticate(), RBACMiddleware.checkRole([Role.ADMIN, Role.INSTRUCTOR]), RoadmapController.createRoadmap);
apiRouter.get('/roadmaps', AuthMiddleware.authenticate(), RoadmapController.getRoadmaps);
apiRouter.get('/roadmaps/:id', AuthMiddleware.authenticate(), RoadmapController.getRoadmap);
apiRouter.post('/roadmaps/:id/enroll', AuthMiddleware.authenticate(), RoadmapController.enrollRoadmap);

// Challenge routes
apiRouter.post('/challenges', AuthMiddleware.authenticate(), RBACMiddleware.checkRole([Role.ADMIN]), ChallengeController.createChallenge);
apiRouter.get('/challenges', AuthMiddleware.authenticate(), ChallengeController.getChallenges);
apiRouter.get('/challenges/:id', AuthMiddleware.authenticate(), ChallengeController.getChallenge);
apiRouter.post('/challenges/:id/submit', AuthMiddleware.authenticate(), ChallengeController.submitChallenge);
apiRouter.get('/challenges/:id/leaderboard', AuthMiddleware.authenticate(), ChallengeController.getLeaderboard);

// Exam routes
apiRouter.post('/exams', AuthMiddleware.authenticate(), RBACMiddleware.checkRole([Role.ADMIN, Role.INSTRUCTOR]), ExamController.createExam);
apiRouter.get('/exams/:id', AuthMiddleware.authenticate(), ExamController.getExam);
apiRouter.post('/exams/:id/submit', AuthMiddleware.authenticate(), ExamController.submitExam);
apiRouter.get('/certificates', AuthMiddleware.authenticate(), ExamController.getCertificates);
apiRouter.get('/certificates/verify/:code', ExamController.verifyCertificate);

// Course routes
// إضافة نقطة نهاية جديدة لجلب الكورسات بدون صلاحيات
apiRouter.get('/courses', async (req: Request, res: Response) => {
  try {
    const { limit = 100, cursor } = req.query;
    const result = await courseService.getCoursesPublic(
      parseInt(limit as string),
      cursor as string | undefined
    );
    res.json({ success: true, data: result });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});
apiRouter.post('/courses', AuthMiddleware.authenticate(),  RBACMiddleware.checkRole([Role.ADMIN, Role.INSTRUCTOR]), CourseController.createCourse);
apiRouter.get('/courses/:id', CourseController.getCourse);
apiRouter.put('/courses/:id', AuthMiddleware.authenticate(),  RBACMiddleware.checkRole([Role.ADMIN, Role.INSTRUCTOR]), CourseController.updateCourse);
apiRouter.delete('/courses/:id', AuthMiddleware.authenticate(), RBACMiddleware.checkRole([Role.ADMIN, Role.INSTRUCTOR]), CourseController.softDeleteCourse);
apiRouter.post('/courses/:id/restore', AuthMiddleware.authenticate(), RBACMiddleware.checkRole([Role.ADMIN, Role.INSTRUCTOR]), CourseController.restoreCourse);

// Lesson routes
apiRouter.post('/courses/:courseId/lessons', AuthMiddleware.authenticate(),  RBACMiddleware.checkRole([Role.INSTRUCTOR]), ValidationMiddleware.validate(lessonCreateSchema), LessonController.createLesson);
apiRouter.get('/courses/:courseId/lessons', AuthMiddleware.authenticate(),  LessonController.getLessonsByCourse);
apiRouter.get('/courses/:courseId/lessons/:id', AuthMiddleware.authenticate(),  LessonController.getLesson);
apiRouter.put('/courses/:courseId/lessons/:id', AuthMiddleware.authenticate(),  RBACMiddleware.checkRole([Role.INSTRUCTOR]), LessonController.updateLesson);
apiRouter.delete('/courses/:courseId/lessons/:id', AuthMiddleware.authenticate(), RBACMiddleware.checkRole([Role.ADMIN, Role.INSTRUCTOR]), LessonController.softDeleteLesson);
apiRouter.post('/courses/:courseId/lessons/:id/restore', AuthMiddleware.authenticate(), RBACMiddleware.checkRole([Role.ADMIN, Role.INSTRUCTOR]), LessonController.restoreLesson);
apiRouter.delete('/courses/:courseId/lessons/:id/permanent', AuthMiddleware.authenticate(), RBACMiddleware.checkRole([Role.ADMIN]), LessonController.permanentDeleteLesson);

// Category routes
apiRouter.post('/categories', AuthMiddleware.authenticate(), RBACMiddleware.checkRole([Role.ADMIN]), CategoryController.createCategory);
apiRouter.get('/categories/:id', CategoryController.getCategory);
apiRouter.put('/categories/:id', AuthMiddleware.authenticate(), RBACMiddleware.checkRole([Role.ADMIN]), CategoryController.updateCategory);
apiRouter.delete('/categories/:id', AuthMiddleware.authenticate(), RBACMiddleware.checkRole([Role.ADMIN]), CategoryController.softDeleteCategory);
apiRouter.post('/categories/:id/restore', AuthMiddleware.authenticate(), RBACMiddleware.checkRole([Role.ADMIN]), CategoryController.restoreCategory);
apiRouter.delete('/categories/:id/permanent', AuthMiddleware.authenticate(), RBACMiddleware.checkRole([Role.ADMIN]), CategoryController.permanentDeleteCategory);

// Enrollment routes
apiRouter.get('/enrollments',
  AuthMiddleware.authenticate(),
  async (req: Request, res: Response , next: NextFunction) => {
    try {
      const userId = req.query.userId as string;
      if (!userId) {
        throw new HttpError(400, 'User ID is required');
      }
      
      const enrollments = await enrollmentRepo.findMany({ userId });
      res.json({ success: true, data: enrollments });
    } catch (error) {
      next(error);
    }
  }
);

// أضف هذا في قسم enrollment routes
apiRouter.get('/enrollments/:userId/:courseId',
  AuthMiddleware.authenticate(),
  async (req: Request, res: Response , next: NextFunction) => {
    try {
      const { userId, courseId } = req.params;
      const enrollment = await enrollmentRepo.findByUserAndCourse(userId, courseId);
      
      if (!enrollment) {
        throw new HttpError(404, 'Enrollment not found');
      }
      
      res.json({ success: true, data: enrollment });
    } catch (error) {
      next(error);
    }
  }
);
apiRouter.post('/enrollments', AuthMiddleware.authenticate(),  EnrollmentController.enroll);
apiRouter.put('/enrollments/progress', AuthMiddleware.authenticate(),  EnrollmentController.updateProgress);

// Support routes
apiRouter.post('/support/conversations', AuthMiddleware.authenticate(),  SupportController.createConversation);
apiRouter.post('/support/conversations/:id/messages', AuthMiddleware.authenticate(),  SupportController.addMessage);

// Admin routes
apiRouter.get('/admin/dashboard', AuthMiddleware.authenticate(), RBACMiddleware.checkRole([Role.ADMIN]), AdminController.getDashboard);

// HR routes
apiRouter.get('/hr/instructors', AuthMiddleware.authenticate(), RBACMiddleware.checkRole([Role.ADMIN, Role.HR]), HrController.getInstructors);
apiRouter.post('/hr/assign-instructor', AuthMiddleware.authenticate(), RBACMiddleware.checkRole([Role.ADMIN, Role.HR]), ValidationMiddleware.validate(assignInstructorSchema), HrController.assignInstructor);

// new advanced routes
apiRouter.post('/users/:userId/learning-profile', 
  AuthMiddleware.authenticate(), 
  LearningProfileController.createOrUpdateProfile
);

apiRouter.get('/users/:userId/learning-profile/analyze', 
  AuthMiddleware.authenticate(), 
  LearningProfileController.analyzeLearningPatterns
);

apiRouter.get('/users/:userId/recommendations', 
  AuthMiddleware.authenticate(), 
  RecommendationController.getRecommendations
);

apiRouter.post('/adaptive/:userId/courses/:courseId/lessons/:lessonId/adjust', 
  AuthMiddleware.authenticate(), 
  AdaptiveLearningController.adjustContentDifficulty
);

apiRouter.post('/users/:userId/learning-path', 
  AuthMiddleware.authenticate(), 
  AdaptiveLearningController.generateLearningPath
);

apiRouter.get('/analytics/:userId/courses/:courseId/prediction', 
  AuthMiddleware.authenticate(), 
  AnalyticsController.predictCompletion
);

apiRouter.get('/analytics/courses/:courseId/at-risk-students', 
  AuthMiddleware.authenticate(), 
  RBACMiddleware.checkRole([Role.ADMIN, Role.INSTRUCTOR]), 
  AnalyticsController.getAtRiskStudents
);

// Bin routes
apiRouter.get('/bin', AuthMiddleware.authenticate(), RBACMiddleware.checkRole([Role.ADMIN]), BinController.getDeletedItems);
apiRouter.post('/:collection/:id/restore', AuthMiddleware.authenticate(), RBACMiddleware.checkRole([Role.ADMIN]), BinController.restoreItem);
apiRouter.delete('/:collection/:id/permanent', AuthMiddleware.authenticate(), RBACMiddleware.checkRole([Role.ADMIN]), BinController.permanentDelete);

// أضف هذا بعد تعريف الـ UploadMiddleware
// Upload route
apiRouter.post('/upload',
  AuthMiddleware.authenticate(),
  UploadMiddleware.setup().single('file'),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      if (!req.file) {
        throw new HttpError(400, 'No file uploaded');
      }
      
      // Determine destination path based on file type
      let destinationPath = 'uploads';
      if (req.file.fieldname === 'profile') {
        destinationPath = 'profiles';
      } else if (req.file.fieldname === 'thumbnail') {
        destinationPath = 'thumbnails';
      } else if (req.file.fieldname === 'video') {
        destinationPath = 'videos';
      } else if (req.file.fieldname === 'attachment') {
        destinationPath = 'attachments';
      }
      
      // Upload to Firebase Storage
      const fileUrl = await firebaseStorageService.uploadFile(
        req.file.buffer, 
        req.file.originalname,
        destinationPath
      );
      
      res.json({
        success: true,
        data: { url: fileUrl }
      });
    } catch (error) {
      next(error);
    }
  }
);

// Delete file route
apiRouter.delete('/files',
  AuthMiddleware.authenticate(),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { fileUrl } = req.body;
      if (!fileUrl) {
        throw new HttpError(400, 'File URL is required');
      }
      
      const result = await firebaseStorageService.deleteFile(fileUrl);
      
      res.json({
        success: result,
        data: { message: result ? 'File deleted successfully' : 'Failed to delete file' }
      });
    } catch (error) {
      next(error);
    }
  }
);

// أضف هذا في قسم enrollment routes
// أضف نقطة نهاية للتحقق من صحة الخادم
apiRouter.get('/health', (req: Request, res: Response) => {
  res.json({
    success: true,
    data: {
      status: 'OK',
      timestamp: dayjs().toISOString(),
      uptime: process.uptime(),
      environment: process.env.NODE_ENV || 'development'
    }
  });
});



app.use('/api', apiRouter);
app.use(ErrorHandler.handle());

// Seeding function
async function seedDatabase() {
  const usersCount = (await userRepo.findMany()).data.length;
  if (usersCount > 0) return;

  // Create admin
  const adminUser = await authService.register(
    'Admin User',
    'admin@example.com',
    'Passw0rd!',
    '+123456789',
    Role.ADMIN
  );

  logger.info('Database seeded successfully');
}

// أضف utility function للترحيل
const paginateResults = (results: any[], limit: number, cursor?: string) => {
  let startIndex = 0;
  
  if (cursor) {
    startIndex = results.findIndex(item => item.id === cursor) + 1;
    if (startIndex === 0) startIndex = results.length; // لم يتم العثور على المؤشر
  }
  
  const endIndex = Math.min(startIndex + limit, results.length);
  const paginatedResults = results.slice(startIndex, endIndex);
  
  return {
    data: paginatedResults,
    nextCursor: endIndex < results.length ? paginatedResults[paginatedResults.length - 1].id : null
  };
};

// CLI commands
async function handleCliCommands() {
  if (process.argv.includes('--seed-only')) {
    await seedDatabase();
    process.exit(0);
  }

  if (process.argv.includes('--snapshot')) {
    const snapshotDir = await snapshotService.exportSnapshot();
    logger.info(`Snapshot created: ${snapshotDir}`);
    process.exit(0);
  }

  if (process.argv.includes('--restore-from-snapshot')) {
    const snapshotDir = process.argv[process.argv.indexOf('--restore-from-snapshot') + 1];
    if (!snapshotDir) {
      logger.error('Please provide snapshot directory path');
      process.exit(1);
    }

    await snapshotService.restoreSnapshot(snapshotDir);
    logger.info(`Snapshot restored from: ${snapshotDir}`);
    process.exit(0);
  }
}

// Start/stop functions for testing
let server: any = null;

function start(port = PORT) {
  return new Promise<void>((resolve) => {
    server = app.listen(port, () => {
      logger.info(`Test server running on port ${port}`);
      resolve();
    });
  });
}

function stop() {
  return new Promise<void>((resolve) => {
    if (server) {
      server.close(() => {
        logger.info('Test server stopped');
        resolve();
      });
    } else {
      resolve();
    }
  });
}

// Main execution
handleCliCommands().then(() => {
  // Start server if not running CLI command
  // Main execution - only run if not in serverless environment
if (!process.env.VERCEL && !process.env.NETLIFY) {
  handleCliCommands().then(() => {
    // Start server if not running CLI command
    if (!process.argv.some(arg => arg.startsWith('--'))) {
      app.listen(PORT, async () => {
        await seedDatabase();
        logger.info(`Server running on port ${PORT}`);
        logger.info(`Swagger docs: http://localhost:${PORT}/docs`);
        logger.info(`Firestore: ${firebaseProjectId} (prefix: ${firestorePrefix})`);
        logger.info(`Redis: ${redisClient.status === 'ready' ? 'connected' : 'disconnected'}`);
        logger.info(`Admin credentials: admin@example.com / Passw0rd!`);
        logger.info(`Uploads dir: ${path.resolve(UPLOAD_DIR)}`);
        logger.info(`Data dir: ${path.resolve(DATA_DIR)}`);
      });
    }
  });
}
});

// Export for Vercel serverless functions
export default async function handler(req: Request, res: Response) {
  // Handle serverless function invocation
  return app(req, res);
}

// Export the app for testing and other purposes
export { app, start, stop };